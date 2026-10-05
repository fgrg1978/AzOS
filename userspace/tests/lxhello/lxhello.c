// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// lxhello: a static Linux binary for the Linux personality (RFC-0047).
//
// It is an ordinary static Linux ELF for riscv64 or aarch64: it reads argc,
// argv, envp and the auxiliary vector from the initial stack, and talks to
// the kernel only through Linux syscall numbers (asm-generic table) in
// a7/x8. Nothing here knows about AzOS. It needs no C library: the few
// calls it makes are issued directly, so the same source builds with any
// Linux-targeting C compiler and no sysroot (`make build/lxhello.elf`).
//
// Each check prints `lx: <what> ok` or `lx: <what> FAIL ...`; the last line
// is `lx: done failures=N`. The gate rows (`tools/ci_check.sh`, "linux:")
// run it from the user shell and read those lines.
//
// Calls go through lx_sc*(NR_<name>, ...): `tests/host/seccomp-tests`
// derives this image's profile from those names, mapping each through the
// personality's table (crates/core/linux-abi) to the native numbers it
// reaches. A number issued raw, with no NR_ name, is a probe the
// personality must refuse on its own.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define NR_getcwd          17
#define NR_dup3            24
#define NR_fcntl           25
#define NR_ioctl           29
#define NR_openat          56
#define NR_close           57
#define NR_pipe2           59
#define NR_getdents64      61
#define NR_lseek           62
#define NR_read            63
#define NR_write           64
#define NR_writev          66
#define NR_newfstatat      79
#define NR_fstat           80
#define NR_exit_group      94
#define NR_set_tid_address 96
#define NR_nanosleep       101
#define NR_clock_gettime   113
#define NR_kill            129
#define NR_tgkill          131
#define NR_rt_sigsuspend   133
#define NR_rt_sigaction    134
#define NR_rt_sigprocmask  135
#define NR_rt_sigpending   136
#define NR_uname           160
#define NR_getpid          172
#define NR_getppid         173
#define NR_brk             214
#define NR_clone           220
#define NR_execve          221
#define NR_munmap          215
#define NR_mmap            222
#define NR_mprotect        226
#define NR_wait4           260
#define NR_prctl           167

#define PR_SET_CHILD_SUBREAPER 36
#define PR_GET_CHILD_SUBREAPER 37

#define AT_FDCWD   (-100L)
#define O_RDONLY   0
#define O_WRONLY   1
#define O_CREAT    0100
#define O_TRUNC    01000
#define O_CLOEXEC  02000000
#if defined(__aarch64__)
#define O_DIRECTORY 040000
#else
#define O_DIRECTORY 0200000
#endif

#define ENOENT 2
#define EBADF  9
#define ECHILD 10
#define EACCES 13
#define ENOTTY 25
#define ENOSYS 38
#define ESRCH  3
#define EINTR  4
#define EPIPE  32

static i64 lx_sc6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f)
{
#if defined(__riscv)
    register i64 a7 __asm__("a7") = n;
    register i64 a0 __asm__("a0") = a;
    register i64 a1 __asm__("a1") = b;
    register i64 a2 __asm__("a2") = c;
    register i64 a3 __asm__("a3") = d;
    register i64 a4 __asm__("a4") = e;
    register i64 a5 __asm__("a5") = f;
    __asm__ volatile("ecall"
                     : "+r"(a0)
                     : "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
                     : "memory");
    return a0;
#elif defined(__aarch64__)
    register i64 x8 __asm__("x8") = n;
    register i64 x0 __asm__("x0") = a;
    register i64 x1 __asm__("x1") = b;
    register i64 x2 __asm__("x2") = c;
    register i64 x3 __asm__("x3") = d;
    register i64 x4 __asm__("x4") = e;
    register i64 x5 __asm__("x5") = f;
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
#else
#error "riscv64 or aarch64 only"
#endif
}

#define lx_sc0(n)                   lx_sc6((n), 0, 0, 0, 0, 0, 0)
#define lx_sc1(n, a)                lx_sc6((n), (i64)(a), 0, 0, 0, 0, 0)
#define lx_sc2(n, a, b)             lx_sc6((n), (i64)(a), (i64)(b), 0, 0, 0, 0)
#define lx_sc3(n, a, b, c)          lx_sc6((n), (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define lx_sc4(n, a, b, c, d)       lx_sc6((n), (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)

// The compiler may lower a struct copy or a zeroed array to these two even
// when freestanding; a static binary with no C library provides them.
void *memset(void *d, int c, unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n);
void *memset(void *d, int c, unsigned long n)
{
    volatile u8 *p = d;
    while (n--) *p++ = (u8)c;
    return d;
}
void *memcpy(void *d, const void *s, unsigned long n)
{
    volatile u8 *p = d;
    const u8 *q = s;
    while (n--) *p++ = *q++;
    return d;
}

// ── Output ─────────────────────────────────────────────────────────────────


static int seq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static int mem_eq(const void *a, const void *b, u64 n)
{
    const u8 *x = a, *y = b;
    for (u64 i = 0; i < n; i++) if (x[i] != y[i]) return 0;
    return 1;
}

// One line is built here and written with one call, so a line never splits
// around another writer's.
static char line[256];
static u64 llen;

static void put(const char *s) { while (*s && llen < sizeof line - 1) line[llen++] = *s++; }

static void putn(i64 v)
{
    char b[24];
    int i = 0;
    u64 u = v < 0 ? (u64)(-v) : (u64)v;
    if (v < 0) put("-");
    do { b[i++] = (char)('0' + u % 10); u /= 10; } while (u);
    while (i) { char c[2] = { b[--i], 0 }; put(c); }
}

static void flush(void)
{
    line[llen++] = '\n';
    lx_sc3(NR_write, 1, line, llen);
    llen = 0;
}

static int failures;

static void check(const char *what, int ok, const char *detail, i64 v)
{
    put("lx: "); put(what);
    if (ok) {
        put(" ok");
    } else {
        failures++;
        put(" FAIL "); put(detail); put(" "); putn(v);
    }
    flush();
}

// ── The checks ─────────────────────────────────────────────────────────────

#define AT_NULL   0
#define AT_PHDR   3
#define AT_PHNUM  5
#define AT_PAGESZ 6
#define AT_RANDOM 25

struct timespec { i64 sec, nsec; };

static i64 mono_ns(void)
{
    struct timespec t;
    if (lx_sc2(NR_clock_gettime, 1, &t) != 0) return -1;
    return t.sec * 1000000000L + t.nsec;
}

static char big[2048] __attribute__((aligned(8)));

// ── Stage 3: FP state, fork, execve ────────────────────────────────────────

// Fill f0..f31 (riscv64) / d0..d31 (aarch64) from `seed`, sleep across
// several context switches, and check every register still holds its value.
// The kernel keeps a Linux task's FP file per task; two tasks doing this at
// once on one hart (parent and fork child) catch a file not switched.
#if defined(__riscv)
#define FP_SET(i) "fmv.d.x f" #i ", %[v]\n addi %[v], %[v], 1\n"
#define FP_GET(i) "fmv.x.d t0, f" #i "\n sub t0, t0, %[v]\n or %[bad], %[bad], t0\n addi %[v], %[v], 1\n"
#define FP_PRE ".option push\n.option arch, +d\n"
#define FP_POST ".option pop\n"
#define FP_CLOB "t0"
#else
#define FP_SET(i) "fmov d" #i ", %[v]\n add %[v], %[v], #1\n"
#define FP_GET(i) "fmov x9, d" #i "\n sub x9, x9, %[v]\n orr %[bad], %[bad], x9\n add %[v], %[v], #1\n"
#define FP_PRE ".arch_extension fp\n"
#define FP_POST ""
#define FP_CLOB "x9"
#endif
#define FP_ALL(M) M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9) M(10) M(11) M(12) M(13) M(14) M(15) \
                  M(16) M(17) M(18) M(19) M(20) M(21) M(22) M(23) M(24) M(25) M(26) M(27) M(28) M(29) M(30) M(31)

// Also the thread pointer (tp / TPIDR_EL0), which musl points at its thread
// descriptor: set to a per-task value and checked after the switches.
// Returns 0, or bit 0 for an FP register lost, bit 1 for the thread pointer.
static int fp_hold(u64 seed)
{
    u64 v = seed, bad = 0, tls = seed ^ 0x5a5aUL, tls_now = 0;
#if defined(__riscv)
    __asm__ volatile("mv tp, %0" : : "r"(tls) : "memory");
#else
    __asm__ volatile("msr tpidr_el0, %0" : : "r"(tls) : "memory");
#endif
    __asm__ volatile(FP_PRE FP_ALL(FP_SET) FP_POST : [v] "+r"(v) : : "memory");
    for (int k = 0; k < 4; k++) {
        struct timespec d = { 0, 15 * 1000000L };
        lx_sc2(NR_nanosleep, &d, 0);
    }
    v = seed;
    __asm__ volatile(FP_PRE FP_ALL(FP_GET) FP_POST : [v] "+r"(v), [bad] "+r"(bad) : : FP_CLOB, "memory");
#if defined(__riscv)
    __asm__ volatile("mv %0, tp" : "=r"(tls_now) : : "memory");
#else
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls_now) : : "memory");
#endif
    return (bad != 0 ? 1 : 0) | (tls_now != tls ? 2 : 0);
}

static char *const exec_argv[] = { "lxhello", "exec-child", 0 };

static void stage3(void)
{
    // Fork: the child holds its own FP pattern while the parent holds
    // another, tries a create its row does not allow, and exits with a code
    // that says what it saw.
    i64 pid = lx_sc6(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0, 0);
    if (pid == 0) {
        int code = fp_hold(0x1111000000000000UL) << 2;
        i64 r = lx_sc4(NR_openat, AT_FDCWD, "/fat/LXDENY2.TXT", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (r != -EACCES) code |= 2;
        lx_sc1(NR_exit_group, 40 + code);
    }
    int held = fp_hold(0x2222000000000000UL);
    int st = 0;
    i64 w = lx_sc4(NR_wait4, pid, &st, 0, 0);
    put("lx: fork child status "); putn((st >> 8) & 0xff); flush();
    check("fork+wait4", pid > 0 && w == pid && (st & 0x7f) == 0, "pid", pid);
    int cst = (st >> 8) & 0xff;
    check("fp state kept across switches", (held & 1) == 0 && ((cst - 40) & 4) == 0, "child status", cst);
    check("thread pointer kept across switches", (held & 2) == 0 && ((cst - 40) & 8) == 0, "child status", cst);
    check("fork child holds only its row", cst >= 40 && ((cst - 40) & 2) == 0, "child status", cst);

    // Round 48: an inherited descriptor shares its open file description
    // (one offset) with the parent, as in Linux. The child writes "a", the
    // parent then writes "b": the file is "ab", not "b".
    i64 sf = lx_sc4(NR_openat, AT_FDCWD, "/tmp/LXFORK", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    pid = sf >= 0 ? lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0) : -1;
    if (pid == 0) {
        lx_sc1(NR_exit_group, lx_sc3(NR_write, sf, "a", 1) == 1 ? 0 : 1);
    }
    st = 0;
    if (pid > 0) lx_sc4(NR_wait4, pid, &st, 0, 0);
    i64 wb = sf >= 0 ? lx_sc3(NR_write, sf, "b", 1) : -1;
    if (sf >= 0) lx_sc1(NR_close, sf);
    i64 rf = lx_sc4(NR_openat, AT_FDCWD, "/tmp/LXFORK", O_RDONLY, 0);
    i64 rn = rf >= 0 ? lx_sc3(NR_read, rf, big, 8) : -1;
    if (rf >= 0) lx_sc1(NR_close, rf);
    big[rn > 0 ? rn : 0] = 0;
    put("lx: inherited file reads ["); put(big); put("]"); flush();
    check("fork shares the file offset", sf >= 0 && pid > 0 && wb == 1 && rn == 2 && mem_eq(big, "ab", 2), "bytes", rn);

    // execve of this same image (its own row) in a fork child.
    pid = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
    if (pid == 0) {
        lx_sc3(NR_execve, "/proc/self/exe", exec_argv, 0);
        lx_sc1(NR_exit_group, 99);
    }
    st = 0;
    w = lx_sc4(NR_wait4, pid, &st, 0, 0);
    check("execve", w == pid && ((st >> 8) & 0xff) == 7, "status", (st >> 8) & 0xff);
}

// ── Wave 13: signals ───────────────────────────────────────────────────────

#define SIGUSR1 10
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGTERM 15
#define SIGCHLD 17
#define SA_SIGINFO  4UL
#define SA_RESTORER 0x04000000UL
#define SA_RESTART  0x10000000UL

// The kernel `struct sigaction`: handler, flags, restorer (aarch64 only:
// riscv64 has no SA_RESTORER and returns through the kernel's page), mask.
struct ksa {
    void (*handler)(int, void *, void *);
    u64 flags;
#if defined(__aarch64__)
    void (*restorer)(void);
#endif
    u64 mask;
};

#if defined(__aarch64__)
void lx_restore(void);
__asm__(".globl lx_restore\n"
        "lx_restore:\n"
        "  mov x8, #139\n"
        "  svc 0\n");
#endif

static volatile int sig_seen, sig_info_signo, sig_count;

// A handler that also scrambles every FP register: the frame must give the
// interrupted code its own values back.
static void on_sig(int s, void *info, void *uc)
{
    (void)uc;
    sig_seen = s;
    sig_info_signo = info ? *(int *)info : -1;
    sig_count++;
    u64 v = 0x7777000000000000UL;
    __asm__ volatile(FP_PRE FP_ALL(FP_SET) FP_POST : [v] "+r"(v) : : "memory");
}

static i64 set_handler(int s, void (*h)(int, void *, void *), u64 flags)
{
    struct ksa a;
    memset(&a, 0, sizeof a);
    a.handler = h;
    a.flags = flags | SA_SIGINFO;
#if defined(__aarch64__)
    a.flags |= SA_RESTORER;
    a.restorer = lx_restore;
#endif
    return lx_sc4(NR_rt_sigaction, s, &a, 0, 8);
}

static i64 set_disp(int s, u64 h)
{
    struct ksa a;
    memset(&a, 0, sizeof a);
    a.handler = (void (*)(int, void *, void *))h;
    return lx_sc4(NR_rt_sigaction, s, &a, 0, 8);
}

// The child's exit code, or 1000 + the signal that killed it (WIFSIGNALED:
// the low 7 bits of the status), as Linux reports it; -1 if wait4 failed.
static int wait_status(i64 pid)
{
    int st = 0;
    i64 w;
    do { w = lx_sc4(NR_wait4, pid, &st, 0, 0); } while (w == -EINTR);
    if (w != pid) return -1;
    return (st & 0x7f) ? 1000 + (st & 0x7f) : (st >> 8) & 0xff;
}

static void stage_signals(void)
{
    i64 me = lx_sc0(NR_getpid);

    // A handler runs at the kill's own return, with siginfo, and the
    // interrupted code (FP file included) continues as it was.
    i64 r = set_handler(SIGUSR1, on_sig, 0);
    u64 v = 0x1234000000000000UL, bad = 0;
    __asm__ volatile(FP_PRE FP_ALL(FP_SET) FP_POST : [v] "+r"(v) : : "memory");
    i64 k = lx_sc2(NR_kill, me, SIGUSR1);
    v = 0x1234000000000000UL;
    __asm__ volatile(FP_PRE FP_ALL(FP_GET) FP_POST : [v] "+r"(v), [bad] "+r"(bad) : : FP_CLOB, "memory");
    put("lx: signal handler sig="); putn(sig_seen); put(" info="); putn(sig_info_signo); put(" kill="); putn(k);
    flush();
    check("signal handler", r == 0 && k == 0 && sig_seen == SIGUSR1 && sig_info_signo == SIGUSR1, "sig", sig_seen);
    check("sigreturn restores fp", bad == 0, "bad", (i64)bad);

    // Blocked: pending, not run; unblocked: run at that call's return.
    set_handler(SIGUSR2, on_sig, 0);
    u64 set = 1UL << (SIGUSR2 - 1), pend = 0;
    sig_seen = 0;
    lx_sc4(NR_rt_sigprocmask, 0 /* SIG_BLOCK */, &set, 0, 8);
    lx_sc3(NR_tgkill, me, me, SIGUSR2);
    int before = sig_seen;
    lx_sc2(NR_rt_sigpending, &pend, 8);
    lx_sc4(NR_rt_sigprocmask, 1 /* SIG_UNBLOCK */, &set, 0, 8);
    check("signal mask", before == 0 && (pend & set) && sig_seen == SIGUSR2, "seen", sig_seen);

    // SIGCHLD reaches the parent when a child exits (the earlier signal
    // state check left it blocked).
    set_handler(SIGCHLD, on_sig, SA_RESTART);
    u64 chld = 1UL << (SIGCHLD - 1);
    lx_sc4(NR_rt_sigprocmask, 1 /* SIG_UNBLOCK */, &chld, 0, 8);
    sig_seen = 0;
    i64 pid = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
    if (pid == 0) lx_sc1(NR_exit_group, 0);
    int cs = wait_status(pid);
    for (int i = 0; i < 50 && sig_seen != SIGCHLD; i++) {
        struct timespec d = { 0, 2 * 1000000L };
        lx_sc2(NR_nanosleep, &d, 0);
    }
    check("sigchld", cs == 0 && sig_seen == SIGCHLD, "seen", sig_seen);
    set_disp(SIGCHLD, 0);

    // A default action ends the task with 128 + signo.
    pid = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
    if (pid == 0) {
        lx_sc2(NR_kill, lx_sc0(NR_getpid), SIGTERM);
        lx_sc1(NR_exit_group, 1);
    }
    cs = wait_status(pid);
    put("lx: sigterm default: wait status "); putn(cs); flush();
    check("default action", cs == 1000 + SIGTERM, "status", cs);
    check("wait4 reports a signalled child WIFSIGNALED", cs == 1000 + SIGTERM, "status", cs);

    // SIGPIPE: ignored, the write answers -EPIPE; by default it ends the
    // writer with 128 + 13.
    int pf[2];
    lx_sc2(NR_pipe2, pf, 0);
    lx_sc1(NR_close, pf[0]);
    set_disp(SIGPIPE, 1 /* SIG_IGN */);
    r = lx_sc3(NR_write, pf[1], "x", 1);
    set_disp(SIGPIPE, 0);
    pid = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
    if (pid == 0) {
        lx_sc3(NR_write, pf[1], "x", 1);
        lx_sc1(NR_exit_group, 1);
    }
    lx_sc1(NR_close, pf[1]);
    cs = wait_status(pid);
    put("lx: sigpipe ignored -> "); putn(r); put(", default: wait status "); putn(cs); flush();
    check("sigpipe", r == -EPIPE && cs == 1000 + SIGPIPE, "status", cs);

    // The parent signals its child: a sleep ends with -EINTR (no
    // SA_RESTART), and the child may not signal its parent (-ESRCH).
    pid = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
    if (pid == 0) {
        i64 up = lx_sc2(NR_kill, lx_sc0(NR_getppid), SIGTERM);
        struct timespec d = { 5, 0 };
        i64 sl = lx_sc2(NR_nanosleep, &d, 0);
        lx_sc1(NR_exit_group, (up == -ESRCH ? 1 : 0) | (sl == -EINTR ? 2 : 0) | (sig_seen == SIGUSR1 ? 4 : 0));
    }
    struct timespec d0 = { 0, 100 * 1000000L };
    lx_sc2(NR_nanosleep, &d0, 0);
    sig_seen = 0;
    k = lx_sc2(NR_kill, pid, SIGUSR1);
    cs = wait_status(pid);
    put("lx: child signalled status "); putn(cs); flush();
    check("kill a child: eintr + handler", k == 0 && cs >= 0 && (cs & 6) == 6, "status", cs);
    check("kill the parent refused", cs >= 0 && (cs & 1) == 1, "status", cs);

    // A task computing without a syscall takes its signal at an interrupt.
    pid = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
    if (pid == 0) {
        sig_seen = 0;
        for (u64 i = 0; i < 4000000000UL && sig_seen != SIGUSR1; i++) {
            __asm__ volatile("" ::: "memory");
        }
        lx_sc1(NR_exit_group, sig_seen == SIGUSR1 ? 9 : 8);
    }
    lx_sc2(NR_nanosleep, &d0, 0);
    lx_sc2(NR_kill, pid, SIGUSR1);
    cs = wait_status(pid);
    check("signal delivered at an interrupt", cs == 9, "status", cs);
}

static volatile u64 bench_hits;
static void on_bench(int s, void *info, void *uc) { (void)s; (void)info; (void)uc; bench_hits++; }

// Wave 13: the signal lanes, the same binary on AzOS (under the
// personality) and on Linux (as an initramfs's /init). Under
// `-icount shift=0` a nanosecond is an instruction: each line reads as
// instructions per 1000 operations plus the loop.
static void bench(void)
{
    i64 me = lx_sc0(NR_getpid);
    i64 b0 = mono_ns();
    for (int i = 0; i < 1000; i++) lx_sc0(NR_getpid);
    i64 b1 = mono_ns();
    put("lx: bench getpid x1000 ns="); putn(b1 - b0); flush();
    set_handler(SIGUSR1, on_bench, 0);
    bench_hits = 0;
    b0 = mono_ns();
    for (int i = 0; i < 1000; i++) lx_sc2(NR_kill, me, SIGUSR1);
    b1 = mono_ns();
    put("lx: bench sigrt x1000 ns="); putn(b1 - b0); put(" handled="); putn((i64)bench_hits); flush();
    u64 set = 1UL << (SIGUSR2 - 1), old = 0;
    b0 = mono_ns();
    for (int i = 0; i < 1000; i++) lx_sc4(NR_rt_sigprocmask, i & 1 ? 1 : 0, &set, &old, 8);
    b1 = mono_ns();
    put("lx: bench sigprocmask x1000 ns="); putn(b1 - b0); flush();
}

// Wave 13: an orphan goes to its nearest ancestor marked a child subreaper,
// as on Linux. A child S marks itself, forks M, M forks C and exits; C waits
// (clock deadline) for getppid() to name S and exits 0x5A (0x5B if it never
// does); S reaps M by pid, then C with wait4(-1), and exits with a bit per
// failed step. Canary `orphan-reparent-canary`: C's parent stays the dead M,
// its exit notice is dropped, and S's wait4(-1) finds no child.
static void stage_orphans(void)
{
    i64 s = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
    if (s == 0) {
        int bad = 0;
        i64 me = lx_sc0(NR_getpid);
        if (lx_sc2(NR_prctl, PR_SET_CHILD_SUBREAPER, 1) != 0) bad |= 1;
        int on = 0;
        if (lx_sc2(NR_prctl, PR_GET_CHILD_SUBREAPER, &on) != 0 || on != 1) bad |= 2;
        i64 m = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
        if (m == 0) {
            i64 c = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
            if (c == 0) {
                i64 end = mono_ns() + 5000000000L;
                while (mono_ns() < end) {
                    if (lx_sc0(NR_getppid) == me) lx_sc1(NR_exit_group, 0x5A);
                    struct timespec d = { 0, 5 * 1000000L };
                    lx_sc2(NR_nanosleep, &d, 0);
                }
                lx_sc1(NR_exit_group, 0x5B);
            }
            lx_sc1(NR_exit_group, c > 0 ? 0 : 1);
        }
        int st = 0;
        if (m <= 0 || lx_sc4(NR_wait4, m, &st, 0, 0) != m || st != 0) bad |= 4;
        st = 0;
        i64 w = lx_sc4(NR_wait4, -1, &st, 0, 0);
        if (w <= 0) bad |= 8;
        else if (((st >> 8) & 0xff) != 0x5A) bad |= 16;
        lx_sc1(NR_exit_group, bad);
    }
    int st = 0;
    i64 w = s > 0 ? lx_sc4(NR_wait4, s, &st, 0, 0) : -1;
    put("lx: orphan subreaper bits "); putn((st >> 8) & 0xff); flush();
    check("orphan adopted by its subreaper", w == s && (st & 0x7f) == 0 && ((st >> 8) & 0xff) == 0,
          "bits", (st >> 8) & 0xff);
}

static void run(i64 *sp)
{
    i64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    if ((argc == 2 && seq(argv[1], "bench")) || (argc >= 1 && seq(argv[0], "/init"))) {
        bench();
        put("lx: bench done"); flush();
        lx_sc1(NR_exit_group, 0);
    }
    if (argc == 2 && seq(argv[1], "exec-child")) {
        put("lx: exec child argc="); putn(argc); put(" ok"); flush();
        lx_sc1(NR_exit_group, 7);
    }
    // Wave 13: `lxhello orphan` forks a grandchild of the shell and exits at
    // once. The grandchild waits (clock deadline) for its parent link to
    // move off this dead task, prints where it went, and exits 90 when it
    // was adopted (91 when its parent became nobody). The shell, a child
    // subreaper, adopts it and its reap prints the status.
    if (argc == 2 && seq(argv[1], "orphan")) {
        i64 me = lx_sc0(NR_getpid);
        i64 c = lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0);
        if (c == 0) {
            i64 end = mono_ns() + 5000000000L, pp = me;
            while (mono_ns() < end && (pp = lx_sc0(NR_getppid)) == me) {
                struct timespec d = { 0, 5 * 1000000L };
                lx_sc2(NR_nanosleep, &d, 0);
            }
            put("lx: orphan ppid="); putn(pp); put(pp != me && pp != 0 ? " adopted" : " not adopted"); flush();
            lx_sc1(NR_exit_group, pp != me && pp != 0 ? 90 : 91);
        }
        put("lx: orphan forked, parent exits"); flush();
        lx_sc1(NR_exit_group, c > 0 ? 0 : 1);
    }
    char **envp = argv + argc + 1;
    char **e = envp;
    while (*e) e++;
    u64 *auxv = (u64 *)(e + 1);

    put("lx: hello from a static Linux ELF, argc="); putn(argc);
    for (i64 i = 0; i < argc; i++) { put(" ["); put(argv[i]); put("]"); }
    flush();
    for (char **p = envp; *p; p++) { put("lx: env "); put(*p); flush(); }

    // The auxiliary vector: the page size, 16 random bytes, and program
    // headers that are really this image's (a PT_LOAD of type 1 among them).
    u64 pagesz = 0, phdr = 0, phnum = 0, random = 0;
    for (u64 *a = auxv; a[0] != AT_NULL; a += 2) {
        if (a[0] == AT_PAGESZ) pagesz = a[1];
        if (a[0] == AT_PHDR) phdr = a[1];
        if (a[0] == AT_PHNUM) phnum = a[1];
        if (a[0] == AT_RANDOM) random = a[1];
    }
    int loads = 0;
    for (u64 i = 0; phdr && i < phnum; i++)
        if (*(u32 *)(phdr + i * 56) == 1) loads++;
    int rnd = 0;
    for (int i = 0; random && i < 16; i++) rnd |= ((u8 *)random)[i];
    check("auxv", pagesz >= 4096 && loads > 0 && rnd != 0, "pagesz/PT_LOADs/random", (i64)pagesz);

    // set_tid_address answers the caller's thread id: its pid here.
    i64 pid = lx_sc0(NR_getpid);
    check("getpid", pid > 0 && lx_sc1(NR_set_tid_address, 0) == pid, "pid", pid);
    check("getppid", lx_sc0(NR_getppid) > 0, "ppid", lx_sc0(NR_getppid));

    // uname: "Linux", and the machine this binary was built for.
    static char uts[390];
    i64 r = lx_sc1(NR_uname, uts);
#if defined(__aarch64__)
    const char *machine = "aarch64";
#else
    const char *machine = "riscv64";
#endif
    check("uname", r == 0 && seq(uts, "Linux") && seq(uts + 4 * 65, machine), "rc", r);

    // getcwd: 17 is SYS_SPAWN for a native task and getcwd here.
    r = lx_sc2(NR_getcwd, big, sizeof big);
    check("getcwd", r > 0 && big[0] == '/', "rc", r);
    put("lx: cwd "); put(big); flush();

    // Time: monotonic, and a 20 ms nanosleep that takes at least 20 ms.
    i64 t0 = mono_ns();
    struct timespec d = { 0, 20 * 1000000L };
    r = lx_sc2(NR_nanosleep, &d, 0);
    i64 t1 = mono_ns();
    check("nanosleep", r == 0 && t0 > 0 && t1 - t0 >= 20 * 1000000L, "elapsed ns", t1 - t0);

    // brk: grow by two pages and use them.
    u64 cur = (u64)lx_sc1(NR_brk, 0);
    u64 want = cur + 8192;
    u64 got = (u64)lx_sc1(NR_brk, want);
    if (got == want) { ((volatile u8 *)cur)[0] = 1; ((volatile u8 *)cur)[8191] = 2; }
    check("brk", cur != 0 && got == want, "got", (i64)got);

    // mmap: anonymous, private, read-write; touch it; unmap it.
    u64 m = (u64)lx_sc6(NR_mmap, 0, 16384, 3, 0x22, -1, 0);
    int mok = (i64)m > 0;
    if (mok) { ((volatile u8 *)m)[0] = 7; ((volatile u8 *)m)[16383] = 9; mok = ((volatile u8 *)m)[16383] == 9; }
    check("mmap", mok && lx_sc2(NR_munmap, m, 16384) == 0, "addr", (i64)m);

    // Wave 13 (security): PROT_READ/PROT_WRITE are exact. A store to a
    // PROT_READ page kills the storer with SIGSEGV (wait status 11); mprotect
    // makes a read-write page read-only and back, a PROT_NONE mapping usable,
    // and refuses PROT_EXEC. Canary `mmap-prot-canary`: the stores succeed.
    {
        // Killed by SIGSEGV: a signal status, or (until signal delivery
        // lands) the exit status 128+11 the kernel reports for a fault.
#define SEGV(st) (((st) & 0x7f) == 11 || (((st) >> 8) & 0xff) == 139)
        u64 ro = (u64)lx_sc6(NR_mmap, 0, 4096, 1 /* PROT_READ */, 0x22, -1, 0);
        int st = -1;
        i64 c = (i64)ro > 0 ? lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0) : -1;
        if (c == 0) { ((volatile u8 *)ro)[0] = 1; lx_sc1(NR_exit_group, 0x77); }
        if (c > 0) lx_sc4(NR_wait4, c, &st, 0, 0);
        check("mprot: a store to PROT_READ memory faults", c > 0 && SEGV(st), "status", st);
        check("mprot: PROT_READ memory reads zero", (i64)ro > 0 && ((volatile u8 *)ro)[0] == 0, "addr", (i64)ro);
        u64 rw = (u64)lx_sc6(NR_mmap, 0, 4096, 3, 0x22, -1, 0);
        if ((i64)rw > 0) ((volatile u8 *)rw)[0] = 5;
        i64 p1 = lx_sc3(NR_mprotect, rw, 4096, 1);
        st = -1;
        c = p1 == 0 ? lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0) : -1;
        if (c == 0) { ((volatile u8 *)rw)[0] = 6; lx_sc1(NR_exit_group, 0x77); }
        if (c > 0) lx_sc4(NR_wait4, c, &st, 0, 0);
        check("mprot: mprotect(PROT_READ) makes a store fault", p1 == 0 && c > 0 && SEGV(st), "status", st);
        i64 px = lx_sc3(NR_mprotect, rw, 4096, 5 /* READ|EXEC */);
        check("mprot: mprotect(PROT_EXEC) is refused", px == -13, "rc", px);
        i64 p2 = lx_sc3(NR_mprotect, rw, 4096, 3);
        if (p2 == 0) ((volatile u8 *)rw)[0] = 8;
        check("mprot: mprotect back to read-write", p2 == 0 && ((volatile u8 *)rw)[0] == 8, "rc", p2);
        u64 nn = (u64)lx_sc6(NR_mmap, 0, 8192, 0 /* PROT_NONE */, 0x22, -1, 0);
        i64 p3 = (i64)nn > 0 ? lx_sc3(NR_mprotect, nn + 4096, 4096, 3) : -1;
        if (p3 == 0) ((volatile u8 *)nn)[4096 + 1] = 4;
        check("mprot: a PROT_NONE mapping made read-write", p3 == 0 && ((volatile u8 *)nn)[4097] == 4, "rc", p3);
        // Wave 14 (security): a fork shares a read-only page with its child
        // as it is. The child's mprotect(RW) and store must land on a copy of
        // its own: the parent's byte stays, the child reads its write.
        // Canary `mprotect-shared-canary`: the store lands in the parent's
        // frame.
        u64 sh = (u64)lx_sc6(NR_mmap, 0, 4096, 3, 0x22, -1, 0);
        if ((i64)sh > 0) ((volatile u8 *)sh)[0] = 0x5a;
        i64 p4 = (i64)sh > 0 ? lx_sc3(NR_mprotect, sh, 4096, 1) : -1;
        st = -1;
        c = p4 == 0 ? lx_sc6(NR_clone, 17, 0, 0, 0, 0, 0) : -1;
        if (c == 0) {
            i64 q = lx_sc3(NR_mprotect, sh, 4096, 3);
            if (q == 0) ((volatile u8 *)sh)[0] = 0xa5;
            lx_sc1(NR_exit_group, q == 0 && ((volatile u8 *)sh)[0] == 0xa5 ? 0 : 1);
        }
        if (c > 0) lx_sc4(NR_wait4, c, &st, 0, 0);
        check("mprot: a fork child's mprotect(RW) write is its own", p4 == 0 && c > 0 && st == 0, "status", st);
        check("mprot: the parent's read-only page is unchanged",
              (i64)sh > 0 && ((volatile u8 *)sh)[0] == 0x5a, "byte", (i64)sh > 0 ? ((volatile u8 *)sh)[0] : -1);
        if ((i64)sh > 0) lx_sc2(NR_munmap, sh, 4096);
        if ((i64)ro > 0) lx_sc2(NR_munmap, ro, 4096);
        if ((i64)rw > 0) lx_sc2(NR_munmap, rw, 4096);
        if ((i64)nn > 0) lx_sc2(NR_munmap, nn, 8192);
    }

    // The console is a terminal: TIOCGWINSZ and TCGETS answer.
    u16 ws[4] = { 0 };
    u32 tio[9] = { 0 };
    r = lx_sc3(NR_ioctl, 1, 0x5413, ws);
    i64 r2 = lx_sc3(NR_ioctl, 1, 0x5401, tio);
    check("ioctl tty", r == 0 && ws[0] > 0 && ws[1] > 0 && r2 == 0 && (tio[3] & 2), "rc", r);

    // Signal state: install SIG_IGN for SIGINT and read it back; block
    // SIGCHLD and read the mask back.
    u64 act[4] = { 1, 0, 0, 0 }, old[4] = { 0 };
    u64 sa = sizeof(u64) * 3;
#if defined(__aarch64__)
    sa = sizeof(u64) * 4;
#endif
    (void)sa;
    r = lx_sc4(NR_rt_sigaction, 2, act, 0, 8);
    r2 = lx_sc4(NR_rt_sigaction, 2, 0, old, 8);
    u64 set = 1UL << (17 - 1), oldset = 0;
    i64 r3 = lx_sc4(NR_rt_sigprocmask, 0, &set, 0, 8);
    i64 r4 = lx_sc4(NR_rt_sigprocmask, 0, 0, &oldset, 8);
    check("signals", r == 0 && r2 == 0 && old[0] == 1 && r3 == 0 && r4 == 0 && oldset == set, "rc", r);

    // A pipe: write through a dup3'd end, read it back.
    int fds[2] = { -1, -1 };
    r = lx_sc2(NR_pipe2, fds, O_CLOEXEC);
    i64 w = -1, n = -1;
    if (r == 0) {
        r2 = lx_sc3(NR_dup3, fds[1], 9, 0);
        lx_sc1(NR_close, fds[1]);
        w = lx_sc3(NR_write, 9, "pipe-bytes", 10);
        n = lx_sc3(NR_read, fds[0], big, 64);
        lx_sc1(NR_close, 9);
        lx_sc1(NR_close, fds[0]);
    }
    check("pipe", r == 0 && r2 == 9 && w == 10 && n == 10 && mem_eq(big, "pipe-bytes", 10), "read", n);
    check("close twice", lx_sc1(NR_close, 9) == -EBADF, "rc", lx_sc1(NR_close, 9));

    // A file: this binary itself. fstat size, ELF magic, lseek to the end
    // and back, and the same 4 bytes again.
    i64 fd = lx_sc4(NR_openat, AT_FDCWD, "/fat/LXHELLO.ELF", O_RDONLY | O_CLOEXEC, 0);
    u64 st[16] = { 0 };
    i64 size = -1, end = -1, again = -1;
    n = -1;
    if (fd >= 0) {
        lx_sc2(NR_fstat, fd, st);
        size = (i64)st[6];
        n = lx_sc3(NR_read, fd, big, 4);
        end = lx_sc3(NR_lseek, fd, 0, 2);
        lx_sc3(NR_lseek, fd, 0, 0);
        again = lx_sc3(NR_read, fd, big + 4, 4);
    }
    int fok = fd >= 0 && size > 4096 && n == 4 && mem_eq(big, "\177ELF", 4) && end == size
              && again == 4 && mem_eq(big + 4, "\177ELF", 4) && (st[2] & 0170000) == 0100000;
    if (!fok) {
        put("lx: file detail fd="); putn(fd); put(" size="); putn(size); put(" read="); putn(n);
        put(" end="); putn(end); put(" again="); putn(again); put(" mode="); putn((i64)(st[2] & 0xffffffff));
        flush();
    }
    check("file", fok, "fd/size", fd < 0 ? fd : size);
    check("ioctl on a file", fd < 0 || lx_sc3(NR_ioctl, fd, 0x5413, ws) == -ENOTTY, "fd", fd);
    if (fd >= 0) lx_sc1(NR_close, fd);

    // newfstatat by path, relative to the working directory the shell gave.
    for (u64 i = 0; i < 16; i++) st[i] = 0;
    r = lx_sc4(NR_newfstatat, AT_FDCWD, "/fat/LXHELLO.ELF", st, 0);
    check("newfstatat", r == 0 && (i64)st[6] == size, "rc", r);
    check("missing file", lx_sc4(NR_openat, AT_FDCWD, "/fat/NOSUCH.TXT", O_RDONLY, 0) == -ENOENT, "", 0);

    // getdents64 over /fat finds this image.
    i64 dfd = lx_sc4(NR_openat, AT_FDCWD, "/fat", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    int found = 0, entries = 0;
    for (;;) {
        n = lx_sc3(NR_getdents64, dfd, big, sizeof big);
        if (n <= 0) break;
        for (i64 off = 0; off < n;) {
            u16 reclen = *(u16 *)(big + off + 16);
            const char *name = big + off + 19;
            entries++;
            if (seq(name, "LXHELLO.ELF")) found = 1;
            off += reclen;
        }
    }
    check("getdents64", dfd >= 0 && found && n == 0, "entries", entries);
    if (dfd >= 0) lx_sc1(NR_close, dfd);

    // writev to the console.
    struct { const char *b; u64 n; } iov[2] = { { "lx: writev ", 11 }, { "ok\n", 3 } };
    r = lx_sc3(NR_writev, 1, iov, 2);
    if (r != 14) check("writev", 0, "rc", r);

    // wait4 with no child: ECHILD.
    check("wait4", lx_sc4(NR_wait4, -1, 0, 0, 0) == -ECHILD, "", 0);

    // fcntl F_GETFD on stdout.
    check("fcntl", lx_sc2(NR_fcntl, 1, 1) >= 0, "", 0);

    // The capability canary. This image's row grants no write authority on
    // /fat, so creating a file there must be refused by the native check
    // (the tree gate), and recorded; the personality must not get around it.
    r = lx_sc4(NR_openat, AT_FDCWD, "/fat/LXDENY.TXT", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    put("lx: create outside caps -> "); putn(r); flush();
    check("create outside caps refused", r == -EACCES, "rc", r);
    if (r >= 0) lx_sc1(NR_close, r);

    // A call the personality does not answer: ENOSYS, never a native call.
    r = lx_sc0(1000);
    check("unanswered call", r == -ENOSYS, "rc", r);

    // The cost of the cheapest translated call: 1000 getpid, timed by the
    // monotonic clock. Under `-icount shift=0` a nanosecond is an
    // instruction, so this reads as instructions per call plus the loop.
    i64 b0 = mono_ns();
    for (int i = 0; i < 1000; i++) lx_sc0(NR_getpid);
    i64 b1 = mono_ns();
    put("lx: bench getpid x1000 ns="); putn(b1 - b0); flush();

    stage3();
    stage_signals();
    stage_orphans();

    put("lx: done failures="); putn(failures); flush();
    lx_sc1(NR_exit_group, failures ? 1 : 0);
}

// The entry point: sp holds argc. Align and hand it to C.
#if defined(__riscv)
__asm__(".globl _start\n"
        "_start:\n"
        "  mv a0, sp\n"
        "  andi sp, sp, -16\n"
        "  call lx_start_c\n"
        "1: j 1b\n");
#else
__asm__(".globl _start\n"
        "_start:\n"
        "  mov x0, sp\n"
        "  and x1, x0, #-16\n"
        "  mov sp, x1\n"
        "  bl lx_start_c\n"
        "1: b 1b\n");
#endif

void lx_start_c(i64 *sp) __attribute__((used, noreturn));
void lx_start_c(i64 *sp)
{
    run(sp);
    for (;;) lx_sc1(NR_exit_group, 2);
}
