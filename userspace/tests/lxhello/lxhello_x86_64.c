// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// lxhello for x86_64: a static Linux x86-64 binary for the ring-3 Linux
// runtime (Kconfig LINUX_RUNTIME, `userspace/services/lxrt`).
//
// `lxhello.c` is written in the asm-generic syscall table (riscv64, aarch64);
// Linux's x86-64 ABI is another one (its own numbers, `syscall` with the
// arguments in rdi rsi rdx r10 r8 r9, a 144-byte `struct stat`, the older
// `open`, `stat`, `pipe`, `dup2` and `fork`). This program issues the calls a
// static x86-64 musl binary issues, so it reads the runtime's x86-64 face
// (`azos_linux_abi::x86_64`) the way a real program does. It runs the same two
// stages as `lxhello rt` and `lxhello spawn`, with the same `lx: ...` lines the
// gate row reads (`tools/gate/ci_check.sh`, "x86_64 linux: hosted by the ring-3
// runtime"), and ends with `lx: rt done failures=N`.
//
// Only what the runtime answers is called, plus the call it must refuse
// (`lseek`: -ENOSYS). The numbers below are musl's
// (`arch/x86_64/bits/syscall.h.in`); `tests/host/linux-abi-tests` reads this
// file and checks every `XNR_` against the runtime's own table, and that the
// runtime answers every call the program issues except the one it refuses.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define XNR_read           0
#define XNR_write          1
#define XNR_open           2
#define XNR_close          3
#define XNR_stat           4
#define XNR_fstat          5
#define XNR_lstat          6
#define XNR_lseek          8
#define XNR_mmap           9
#define XNR_munmap         11
#define XNR_brk            12
#define XNR_rt_sigaction   13
#define XNR_rt_sigprocmask 14
#define XNR_ioctl          16
#define XNR_writev         20
#define XNR_pipe           22
#define XNR_dup            32
#define XNR_dup2           33
#define XNR_nanosleep      35
#define XNR_getpid         39
#define XNR_fork           57
#define XNR_wait4          61
#define XNR_uname          63
#define XNR_fcntl          72
#define XNR_getcwd         79
#define XNR_umask          95
#define XNR_getppid        110
#define XNR_arch_prctl     158
#define XNR_gettid         186
#define XNR_getdents64     217
#define XNR_set_tid_address 218
#define XNR_clock_gettime  228
#define XNR_exit_group     231
#define XNR_openat         257
#define XNR_newfstatat     262

#define AT_FDCWD   (-100L)
#define O_RDONLY   0
#define O_WRONLY   1
#define O_CREAT    0100
#define O_TRUNC    01000
#define O_DIRECTORY 0200000

#define EPERM  1
#define ENOENT 2
#define EBADF  9
#define ECHILD 10
#define EACCES 13
#define ENOTTY 25
#define ENOSYS 38

// The `syscall` instruction: the number in rax, the arguments in rdi rsi rdx
// r10 r8 r9, the result in rax; rcx and r11 are overwritten.
static i64 xsc6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f)
{
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    i64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

#define xsc0(n)                   xsc6((n), 0, 0, 0, 0, 0, 0)
#define xsc1(n, a)                xsc6((n), (i64)(a), 0, 0, 0, 0, 0)
#define xsc2(n, a, b)             xsc6((n), (i64)(a), (i64)(b), 0, 0, 0, 0)
#define xsc3(n, a, b, c)          xsc6((n), (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define xsc4(n, a, b, c, d)       xsc6((n), (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)

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
    xsc3(XNR_write, 1, line, llen);
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

struct timespec { i64 sec, nsec; };

static i64 mono_ns(void)
{
    struct timespec t;
    if (xsc2(XNR_clock_gettime, 1, &t) != 0) return -1;
    return t.sec * 1000000000L + t.nsec;
}

static char big[2048] __attribute__((aligned(8)));

// x86-64 `struct stat` (musl `arch/x86_64/bits/stat.h`): 144 bytes.
struct xstat {
    u64 dev, ino, nlink;
    u32 mode, uid, gid, pad0;
    u64 rdev;
    i64 size, blksize, blocks;
    struct timespec atim, mtim, ctim;
    i64 unused[3];
};
_Static_assert(sizeof(struct xstat) == 144, "struct stat on x86_64");

// ── The stages ─────────────────────────────────────────────────────────────

#define AT_NULL   0
#define AT_PAGESZ 6
#define AT_RANDOM 25

// The initial stack: argc, argv, envp, the auxiliary vector.
static void stage_stack(i64 *sp)
{
    i64 argc = sp[0];
    u64 *p = (u64 *)(sp + 1 + argc + 1);
    while (*p) p++;
    p++;
    u64 pagesz = 0, random = 0;
    for (; p[0] != AT_NULL; p += 2) {
        if (p[0] == AT_PAGESZ) pagesz = p[1];
        if (p[0] == AT_RANDOM) random = p[1];
    }
    check("auxv", pagesz == 4096 && random != 0, "pagesz", (i64)pagesz);
    check("stack aligned", ((u64)sp & 15) == 0, "sp", (i64)sp);
}

// A fork: the child holds its row's authority only and shares the parent's
// open file offset; the parent reaps it with the Linux wait status.
static void stage_fork(void)
{
    // An inherited descriptor shares its open file description (one offset):
    // the child writes "a", the parent then writes "b", the file reads "ab".
    i64 sf = xsc4(XNR_open, (i64)"/tmp/LXFORK", O_WRONLY | O_CREAT | O_TRUNC, 0644, 0);
    i64 pid = sf >= 0 ? xsc0(XNR_fork) : -1;
    if (pid == 0) {
        xsc1(XNR_exit_group, xsc3(XNR_write, sf, "a", 1) == 1 ? 0 : 1);
    }
    int st = 0;
    if (pid > 0) xsc4(XNR_wait4, pid, &st, 0, 0);
    i64 wb = sf >= 0 ? xsc3(XNR_write, sf, "b", 1) : -1;
    if (sf >= 0) xsc1(XNR_close, sf);
    i64 rf = xsc3(XNR_open, (i64)"/tmp/LXFORK", O_RDONLY, 0);
    i64 rn = rf >= 0 ? xsc3(XNR_read, rf, big, 8) : -1;
    if (rf >= 0) xsc1(XNR_close, rf);
    big[rn > 0 ? rn : 0] = 0;
    put("lx: inherited file reads ["); put(big); put("]"); flush();
    check("fork shares the file offset", sf >= 0 && pid > 0 && wb == 1 && rn == 2 && mem_eq(big, "ab", 2), "bytes", rn);

    // Fork, second: under the ring-3 runtime the first fork of a row seeds
    // its child through the row's minters and records the row's template
    // (`natfork`); this child is seeded from that template, so its authority
    // check is the template's.
    i64 ppid = xsc0(XNR_getpid);
    pid = xsc0(XNR_fork);
    if (pid == 0) {
        int code = 0;
        if (xsc0(XNR_getppid) != ppid) code |= 1;
        if (xsc0(XNR_getpid) == ppid) code |= 4;
        i64 r = xsc4(XNR_openat, AT_FDCWD, "/fat/LXDENY2.TXT", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (r != -EACCES) code |= 2;
        xsc1(XNR_exit_group, 40 + code);
    }
    st = 0;
    i64 w = xsc4(XNR_wait4, pid, &st, 0, 0);
    put("lx: fork child status "); putn((st >> 8) & 0xff); flush();
    int cst = (st >> 8) & 0xff;
    check("fork+wait4", pid > 0 && w == pid && (st & 0x7f) == 0, "pid", pid);
    check("fork child ids", cst >= 40 && ((cst - 40) & 5) == 0, "child status", cst);
    check("fork child holds only its row", cst >= 40 && ((cst - 40) & 2) == 0, "child status", cst);
}

// `lxhello rt`: the calls the ring-3 runtime answers over the native ABI.
static void stage_rt(i64 *sp)
{
    stage_stack(sp);
    i64 pid = xsc0(XNR_getpid);
    check("rt: getpid", pid > 0 && xsc1(XNR_set_tid_address, 0) == pid && xsc0(XNR_gettid) == pid, "pid", pid);

    static char uts[390];
    i64 r = xsc1(XNR_uname, uts);
    check("rt: uname", r == 0 && seq(uts, "Linux") && seq(uts + 4 * 65, "x86_64"), "rc", r);

    r = xsc2(XNR_getcwd, big, sizeof big);
    check("rt: getcwd", r > 0 && big[0] == '/', "rc", r);

    i64 u0 = xsc1(XNR_umask, 077);
    i64 u1 = xsc1(XNR_umask, u0);
    check("rt: umask", u0 == 022 && u1 == 077, "umask", u0);

    i64 t0 = mono_ns();
    struct timespec d = { 0, 20 * 1000000L };
    r = xsc2(XNR_nanosleep, &d, 0);
    i64 t1 = mono_ns();
    check("rt: nanosleep", r == 0 && t0 > 0 && t1 - t0 >= 20 * 1000000L, "elapsed ns", t1 - t0);

    u64 cur = (u64)xsc1(XNR_brk, 0);
    u64 want = cur + 8192;
    u64 got = (u64)xsc1(XNR_brk, want);
    if (got == want) { ((volatile u8 *)cur)[0] = 1; ((volatile u8 *)cur)[8191] = 2; }
    check("rt: brk", cur != 0 && got == want, "got", (i64)got);

    // mmap(0, 16 KiB, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0):
    // the flags are the fourth argument, in r10.
    u64 m = (u64)xsc6(XNR_mmap, 0, 16384, 3, 0x22, -1, 0);
    int mok = (i64)m > 0;
    if (mok) { ((volatile u8 *)m)[0] = 7; ((volatile u8 *)m)[16383] = 9; mok = ((volatile u8 *)m)[16383] == 9; }
    check("rt: mmap", mok && xsc2(XNR_munmap, m, 16384) == 0, "addr", (i64)m);

    u16 ws[4] = { 0 };
    u32 tio[9] = { 0 };
    r = xsc3(XNR_ioctl, 1, 0x5413, ws);
    i64 r2 = xsc3(XNR_ioctl, 1, 0x5401, tio);
    check("rt: ioctl tty", r == 0 && ws[0] > 0 && ws[1] > 0 && r2 == 0 && (tio[3] & 2), "rc", r);

    // The x86-64 kernel `struct sigaction`: handler, flags, restorer, mask.
    u64 act[4] = { 1, 0x04000000 /* SA_RESTORER */, 0x1234, 0x8 }, old[4] = { 0 };
    r = xsc4(XNR_rt_sigaction, 2, act, 0, 8);
    r2 = xsc4(XNR_rt_sigaction, 2, 0, old, 8);
    u64 set = 1UL << (17 - 1), oldset = 0;
    i64 r3 = xsc4(XNR_rt_sigprocmask, 0, &set, 0, 8);
    i64 r4 = xsc4(XNR_rt_sigprocmask, 0, 0, &oldset, 8);
    check("rt: signal state", r == 0 && r2 == 0 && old[0] == 1 && old[2] == 0x1234 && old[3] == 0x8 && r3 == 0 && r4 == 0 && oldset == set,
          "rc", r);

    // pipe(2), dup2(2) onto 9, and dup2 onto itself (an open fd answers itself).
    int fds[2] = { -1, -1 };
    r = xsc1(XNR_pipe, fds);
    i64 w = -1, n = -1;
    r2 = -1;
    r3 = -1;
    if (r == 0) {
        r2 = xsc2(XNR_dup2, fds[1], 9);
        r3 = xsc2(XNR_dup2, 9, 9);
        xsc1(XNR_close, fds[1]);
        w = xsc3(XNR_write, 9, "pipe-bytes", 10);
        n = xsc3(XNR_read, fds[0], big, 64);
        xsc1(XNR_close, 9);
        xsc1(XNR_close, fds[0]);
    }
    check("rt: pipe", r == 0 && r2 == 9 && r3 == 9 && w == 10 && n == 10 && mem_eq(big, "pipe-bytes", 10), "read", n);
    check("rt: close twice", xsc1(XNR_close, 9) == -EBADF, "rc", xsc1(XNR_close, 9));
    check("rt: dup2 onto itself, not open", xsc2(XNR_dup2, 9, 9) == -EBADF, "rc", xsc2(XNR_dup2, 9, 9));

    // A file: this binary itself, by size and magic (no seek is offered).
    i64 fd = xsc3(XNR_open, (i64)"/fat/LXHELLO.ELF", O_RDONLY, 0);
    struct xstat st;
    i64 size = -1;
    n = -1;
    memset(&st, 0xAA, sizeof st);
    if (fd >= 0) {
        xsc2(XNR_fstat, fd, &st);
        size = st.size;
        n = xsc3(XNR_read, fd, big, 4);
    }
    check("rt: file", fd >= 0 && size > 4096 && n == 4 && mem_eq(big, "\177ELF", 4) && (st.mode & 0170000) == 0100000
          && st.nlink >= 1 && st.unused[2] == 0, "fd/size", fd < 0 ? fd : size);
    check("rt: ioctl on a file", fd < 0 || xsc3(XNR_ioctl, fd, 0x5413, ws) == -ENOTTY, "fd", fd);
    if (fd >= 0) xsc1(XNR_close, fd);

    memset(&st, 0, sizeof st);
    r = xsc2(XNR_stat, (i64)"/fat/LXHELLO.ELF", &st);
    check("rt: stat", r == 0 && st.size == size && (st.mode & 0170000) == 0100000, "rc", r);
    memset(&st, 0, sizeof st);
    r = xsc2(XNR_lstat, (i64)"/fat/LXHELLO.ELF", &st);
    check("rt: lstat", r == 0 && st.size == size, "rc", r);
    memset(&st, 0, sizeof st);
    r = xsc4(XNR_newfstatat, AT_FDCWD, (i64)"/fat/LXHELLO.ELF", &st, 0);
    check("rt: newfstatat", r == 0 && st.size == size, "rc", r);
    memset(&st, 0, sizeof st);
    r = xsc2(XNR_stat, (i64)"/fat", &st);
    check("rt: stat a directory", r == 0 && (st.mode & 0170000) == 0040000, "rc", r);
    check("rt: missing file", xsc3(XNR_open, (i64)"/fat/NOSUCH.TXT", O_RDONLY, 0) == -ENOENT, "", 0);

    i64 dfd = xsc4(XNR_openat, AT_FDCWD, (i64)"/fat", O_RDONLY | O_DIRECTORY, 0);
    int found = 0, entries = 0;
    for (;;) {
        n = xsc3(XNR_getdents64, dfd, big, sizeof big);
        if (n <= 0) break;
        for (i64 off = 0; off < n;) {
            u16 reclen = *(u16 *)(big + off + 16);
            const char *name = big + off + 19;
            entries++;
            if (seq(name, "LXHELLO.ELF")) found = 1;
            off += reclen;
        }
    }
    check("rt: getdents64", dfd >= 0 && found && n == 0, "entries", entries);
    if (dfd >= 0) xsc1(XNR_close, dfd);

    struct { const char *b; u64 n; } iov[2] = { { "lx: writev ", 11 }, { "ok\n", 3 } };
    r = xsc3(XNR_writev, 1, iov, 2);
    if (r != 14) check("rt: writev", 0, "rc", r);

    check("rt: wait4", xsc4(XNR_wait4, -1, 0, 0, 0) == -ECHILD, "", 0);
    check("rt: fcntl", xsc2(XNR_fcntl, 1, 1) >= 0, "", 0);

    r = xsc3(XNR_open, (i64)"/fat/LXDENY.TXT", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check("rt: create outside caps refused", r == -EACCES, "rc", r);
    if (r >= 0) xsc1(XNR_close, r);

    // What the runtime does not answer: -ENOSYS, under the x86-64 numbers
    // (seek is 8 here; 62 would be kill).
    check("rt: unanswered call", xsc3(XNR_lseek, 3, 0, 0) == -ENOSYS && xsc0(1000) == -ENOSYS, "rc", xsc0(1000));

    // The thread pointer, as musl's start sets it: ARCH_SET_FS (0x1002)
    // resumes this program on a thread started with the new FS base (ring 3
    // cannot write it), so the block is read back through %fs, and
    // ARCH_GET_FS (0x1003) answers the base. The fork stage below runs on
    // it: the child keeps the base.
    static u64 tls_block[2] = { 0, 0x6c78746c73ULL };
    tls_block[0] = (u64)tls_block; // the TCB's self-pointer, as musl's
    u64 base = 0, at_fs = 0;
    r = xsc2(XNR_arch_prctl, 0x1002, tls_block);
    if (r == 0) __asm__ volatile("movq %%fs:8, %0" : "=r"(at_fs));
    i64 g = xsc2(XNR_arch_prctl, 0x1003, &base);
    check("rt: arch_prctl sets the FS base", r == 0 && g == 0 && base == (u64)tls_block && at_fs == tls_block[1], "rc", r);
    r = xsc2(XNR_arch_prctl, 0x1002, 1UL << 47);
    check("rt: arch_prctl refuses a non-canonical base", r == -EPERM, "rc", r);

    stage_fork();

    put("lx: rt done failures="); putn(failures); flush();
    xsc1(XNR_exit_group, failures ? 1 : 0);
}

// `lxhello spawn`: what the spawn request handed this process (the working
// directory, what descriptor 0 is, and what comes in on it until end of file).
// The runner pipes or redirects descriptor 0 and redirects descriptor 1.
static void stage_spawn(void)
{
    i64 r = xsc2(XNR_getcwd, big, sizeof big);
    put("lx: spawn cwd="); put(r > 0 ? big : "?"); flush();

    struct xstat st;
    r = xsc2(XNR_fstat, 0, &st);
    u32 kind = st.mode & 0170000;
    put("lx: spawn stdin kind=");
    put(r != 0 ? "none" : kind == 0010000 ? "fifo" : kind == 0100000 ? "file" : kind == 0020000 ? "tty" : "other");
    flush();

    char got[64];
    i64 n = 0;
    for (;;) {
        i64 k = xsc3(XNR_read, 0, got + n, sizeof got - 1 - n);
        if (k <= 0) break;
        n += k;
        if (n >= (i64)sizeof got - 1) break;
    }
    while (n > 0 && got[n - 1] == '\n') n--;
    got[n] = 0;
    put("lx: spawn stdin=["); put(got); put("]"); flush();
    put("lx: spawn done"); flush();
    xsc1(XNR_exit_group, 0);
}

static void run(i64 *sp)
{
    i64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    if (argc == 2 && seq(argv[1], "rt")) {
        stage_rt(sp);
    }
    if (argc == 2 && seq(argv[1], "spawn")) {
        stage_spawn();
    }
    put("lx: usage: lxhello rt | spawn"); flush();
    xsc1(XNR_exit_group, 2);
}

// The entry point: rsp holds argc, 16-byte aligned; hand it to C.
__asm__(".globl _start\n"
        "_start:\n"
        "  mov %rsp, %rdi\n"
        "  and $-16, %rsp\n"
        "  call lx_start_c\n"
        "  ud2\n");

void lx_start_c(i64 *sp) __attribute__((used, noreturn));
void lx_start_c(i64 *sp)
{
    run(sp);
    for (;;) xsc1(XNR_exit_group, 2);
}
