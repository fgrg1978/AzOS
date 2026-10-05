// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/*
 * Linux half of the periodic-wake TAIL comparison (wave 13, RT7); the AzOS
 * half is kernel/src/smokes/tail_smoke.rs. Same shape, same QEMU (-smp 1
 * -icount shift=0,sleep=off; tools/lat_linux/run.sh tail ...): PAIRS
 * ping-pong pairs of processes on CPU 0 (SCHED_OTHER) pass a 100-byte
 * message over pipes forever (hackbench's pipe groups); a waker sleeps to
 * absolute deadlines PERIOD_NS apart (clock_nanosleep TIMER_ABSTIME,
 * CLOCK_MONOTONIC) for N periods and records now - deadline, twice: as
 * SCHED_FIFO 98 (mode=rt-fifo) and as SCHED_OTHER (mode=best-effort).
 * One `[TAIL]` line each (mean/p50/p99/p99.9/max), then power-off.
 */
typedef unsigned long u64;
typedef long i64;

static i64 sc(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e)
{
#if defined(__riscv)
	register i64 a0 __asm__("a0") = a, a1 __asm__("a1") = b, a2 __asm__("a2") = c, a3 __asm__("a3") = d, a4 __asm__("a4") = e;
	register i64 a7 __asm__("a7") = n;
	__asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7) : "memory");
	return a0;
#else
	register i64 x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c, x3 __asm__("x3") = d, x4 __asm__("x4") = e;
	register i64 x8 __asm__("x8") = n;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
	return x0;
#endif
}

enum {
	SYS_MKDIRAT = 34, SYS_MOUNT = 40, SYS_OPENAT = 56, SYS_PIPE2 = 59, SYS_READ = 63,
	SYS_WRITE = 64, SYS_PREAD64 = 67, SYS_LSEEK = 62, SYS_EXIT = 93, SYS_CLOCK_GETTIME = 113,
	SYS_CLOCK_NANOSLEEP = 115, SYS_SCHED_SETSCHEDULER = 119, SYS_SCHED_SETAFFINITY = 122,
	SYS_REBOOT = 142, SYS_CLONE = 220,
};
#define AT_FDCWD (-100)
#define CLOCK_MONOTONIC 1
#define TIMER_ABSTIME 1
#define SCHED_FIFO 1
#define SIGCHLD 17
#if defined(__riscv)
#define O_DIRECT 040000
#else
#define O_DIRECT 0200000
#endif

#define PERIOD_NS 1000000UL
#define PERIODS 2000
#define SETTLE_NS 1500000000UL
#define SPAM_EVERY 2
#define DISK_SECTORS 8
#define FIFO_PRIO 98

struct ts { i64 s, ns; };

static u64 now(void)
{
	struct ts t;
	sc(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, (i64)&t, 0, 0, 0);
	return (u64)t.s * 1000000000UL + (u64)t.ns;
}

static void sleep_abs(u64 d)
{
	struct ts t = { (i64)(d / 1000000000UL), (i64)(d % 1000000000UL) };
	while (sc(SYS_CLOCK_NANOSLEEP, CLOCK_MONOTONIC, TIMER_ABSTIME, (i64)&t, 0, 0) == -4)
		;
}

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void puts1(const char *s) { sc(SYS_WRITE, 1, (i64)s, (i64)slen(s), 0, 0); }

static char *utoa(char *p, u64 v)
{
	char b[24]; int n = 0;
	do { b[n++] = (char)('0' + v % 10); v /= 10; } while (v);
	while (n) *p++ = b[--n];
	return p;
}
static char *cat(char *p, const char *s) { while (*s) *p++ = *s++; return p; }
static char *kv(char *p, const char *k, i64 v)
{
	p = cat(p, k);
	if (v < 0) { *p++ = '-'; v = -v; }
	return utoa(p, (u64)v);
}

static i64 forkit(void) { return sc(SYS_CLONE, SIGCHLD, 0, 0, 0, 0); }

static void pin0(void)
{
	u64 mask = 1;
	sc(SYS_SCHED_SETAFFINITY, 0, sizeof mask, (i64)&mask, 0, 0);
}


#define PAIRS 4
#define N 10000
#define TAIL_PERIOD_NS 1000000UL

static u64 tsamples[N];

static void sortu(u64 *a, int n)
{
	/* Shell sort: 10k values. */
	for (int gap = n / 2; gap > 0; gap /= 2)
		for (int i = gap; i < n; i++) {
			u64 v = a[i]; int j = i;
			while (j >= gap && a[j - gap] > v) { a[j] = a[j - gap]; j -= gap; }
			a[j] = v;
		}
}

static void run(const char *mode, int fifo, char *line)
{
	struct { int prio; } param = { fifo ? FIFO_PRIO : 0 };
	i64 rc = sc(SYS_SCHED_SETSCHEDULER, 0, fifo ? SCHED_FIFO : 0, (i64)&param, 0, 0);
	u64 t0 = now() + TAIL_PERIOD_NS, max = 0, overruns = 0, sum = 0;
	int worst = 0;
	for (int k = 0; k < N; k++) {
		u64 d = t0 + (u64)k * TAIL_PERIOD_NS;
		if (now() >= d) overruns++;
		sleep_abs(d);
		u64 t = now(), late = t > d ? t - d : 0;
		tsamples[k] = late; sum += late;
		if (late > max) { max = late; worst = k; }
	}
	sortu(tsamples, N);
#if defined(__riscv)
	const char *isa = "riscv64";
#else
	const char *isa = "aarch64";
#endif
	char *p = cat(line, "[TAIL] isa="); p = cat(p, isa);
	p = cat(p, " mode="); p = cat(p, mode);
	p = cat(p, " kernel=linux");
	p = kv(p, " n=", N);
	p = kv(p, " mean_ns=", (i64)(sum / N));
	p = kv(p, " p50_ns=", (i64)tsamples[(N * 50 + 99) / 100 - 1]);
	p = kv(p, " p99_ns=", (i64)tsamples[(N * 99 + 99) / 100 - 1]);
	p = kv(p, " p999_ns=", (i64)tsamples[(N * 999 + 999) / 1000 - 1]);
	p = kv(p, " max_ns=", (i64)max);
	p = kv(p, " worst=", worst);
	p = kv(p, " overruns=", (i64)overruns);
	p = kv(p, " sched_rc=", rc);
	p = cat(p, "\n");
	sc(SYS_WRITE, 1, (i64)line, p - line, 0, 0);
}

int main_(void)
{
	char line[256];
	pin0();
	for (int g = 0; g < PAIRS; g++) {
		int ab[2], ba[2];
		sc(SYS_PIPE2, (i64)ab, 0, 0, 0, 0);
		sc(SYS_PIPE2, (i64)ba, 0, 0, 0, 0);
		for (int side = 0; side < 2; side++) {
			if (forkit() == 0) {
				pin0();
				unsigned char msg[100];
				for (int k = 0; k < 100; k++) msg[k] = (unsigned char)k;
				int rd = side ? ab[0] : ba[0], wr = side ? ba[1] : ab[1];
				if (side == 0) sc(SYS_WRITE, wr, (i64)msg, 100, 0, 0);
				for (;;) {
					i64 got = 0;
					while (got < 100) {
						i64 r = sc(SYS_READ, rd, (i64)msg + got, 100 - got, 0, 0);
						if (r <= 0) sc(SYS_EXIT, 0, 0, 0, 0, 0);
						got += r;
					}
					for (int k = 0; k < 100; k++) msg[k]++;
					sc(SYS_WRITE, wr, (i64)msg, 100, 0, 0);
				}
			}
		}
	}
	sleep_abs(now() + SETTLE_NS);
	run("rt-fifo", 1, line);
	run("best-effort", 0, line);
	puts1("[TAIL] done\n");
	sc(SYS_REBOOT, (i64)0xfee1dead, 672274793, 0x4321fedc, 0, 0);
	for (;;) ;
}

static unsigned char stack[65536] __attribute__((aligned(16), used));
#if defined(__riscv)
__asm__(".globl _start\n_start:\n la sp, stack+65536\n call main_\n");
#else
__asm__(".globl _start\n_start:\n adrp x0, stack+65536\n add x0, x0, :lo12:stack+65536\n mov sp, x0\n bl main_\n");
#endif
