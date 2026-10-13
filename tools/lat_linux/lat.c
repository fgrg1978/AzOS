// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/*
 * Linux counterpart of the AzOS `lat:` rows (kernel/src/lat_smoke.rs), as
 * /init of an initramfs (tools/lat_linux/run.sh). Same shape, same QEMU
 * (-smp 1 -icount shift=0,sleep=off): a SCHED_FIFO task sleeps to absolute
 * deadlines PERIOD_NS apart (clock_nanosleep TIMER_ABSTIME, CLOCK_MONOTONIC)
 * for PERIODS periods and records now - deadline. Load on the same CPU, all
 * below it (SCHED_OTHER), paced by the measurer as on AzOS: a printer
 * writes a ~100-byte console line every SPAM_EVERY periods, a reader does an
 * 8-sector O_DIRECT read of /dev/vda every period (virtio-blk request and
 * completion interrupt), and a hog never blocks. Kicks go through pipes.
 * One line: `[LATLX] isa=... max_ns=... p99_ns=... p50_ns=... min_ns=...`,
 * then `[LATLX] load ...`, then power-off. Static, no C library, raw
 * syscalls of the generic table riscv64 and aarch64 share.
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

static u64 samples[PERIODS];
static unsigned char dbuf[512 * DISK_SECTORS + 4096];

int main_(void)
{
	char line[256], *p;
	pin0();
	/* /dev for the disk: devtmpfs, if the kernel has it. */
	sc(SYS_MKDIRAT, AT_FDCWD, (i64)"/dev", 0755, 0, 0);
	i64 mnt = sc(SYS_MOUNT, (i64)"devtmpfs", (i64)"/dev", (i64)"devtmpfs", 0, 0);
	int kick_spam[2], kick_disk[2], stat_spam[2], stat_disk[2];
	sc(SYS_PIPE2, (i64)kick_spam, 0, 0, 0, 0);
	sc(SYS_PIPE2, (i64)kick_disk, 0, 0, 0, 0);
	sc(SYS_PIPE2, (i64)stat_spam, 0, 0, 0, 0);
	sc(SYS_PIPE2, (i64)stat_disk, 0, 0, 0, 0);

	if (forkit() == 0) { /* hog */
		pin0();
		volatile unsigned x = 0x9E3779B9u;
		for (;;) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; }
	}
	if (forkit() == 0) { /* printer */
		pin0();
		char c; u64 n = 0;
		while (sc(SYS_READ, kick_spam[0], (i64)&c, 1, 0, 0) == 1 && c == 'k') {
			p = cat(line, "[LATLOAD] ");
			p = utoa(p, n++);
			p = cat(p, " the quick brown fox jumps over the lazy dog 0123456789 abcdefghijklmnopqrstuvwxyz\n");
			sc(SYS_WRITE, 1, (i64)line, p - line, 0, 0);
		}
		sc(SYS_WRITE, stat_spam[1], (i64)&n, sizeof n, 0, 0);
		sc(SYS_EXIT, 0, 0, 0, 0, 0);
	}
	if (forkit() == 0) { /* disk reader */
		pin0();
		unsigned char *b = (unsigned char *)(((u64)dbuf + 4095) & ~4095UL);
		i64 fd = sc(SYS_OPENAT, AT_FDCWD, (i64)"/dev/vda", O_DIRECT, 0, 0);
		i64 cap = fd >= 0 ? sc(SYS_LSEEK, fd, 0, 2, 0, 0) / 512 : 0;
		u64 reads = 0, errors = 0, sector = 0;
		char c;
		while (sc(SYS_READ, kick_disk[0], (i64)&c, 1, 0, 0) == 1 && c == 'k') {
			if (fd < 0 || cap < DISK_SECTORS) { errors++; continue; }
			if (sc(SYS_PREAD64, fd, (i64)b, 512 * DISK_SECTORS, (i64)(sector * 512), 0) == 512 * DISK_SECTORS)
				reads++;
			else
				errors++;
			sector = (sector + DISK_SECTORS * 17) % (u64)(cap - DISK_SECTORS);
		}
		u64 out[2] = { reads, errors };
		sc(SYS_WRITE, stat_disk[1], (i64)out, sizeof out, 0, 0);
		sc(SYS_EXIT, 0, 0, 0, 0, 0);
	}

	struct { int prio; } param = { FIFO_PRIO };
	i64 fifo = sc(SYS_SCHED_SETSCHEDULER, 0, SCHED_FIFO, (i64)&param, 0, 0);
	sleep_abs(now() + SETTLE_NS);
	u64 t0 = now() + PERIOD_NS, max = 0, overruns = 0;
	int worst = 0;
	for (int k = 0; k < PERIODS; k++) {
		u64 d = t0 + (u64)k * PERIOD_NS;
		if (now() >= d) overruns++;
		sleep_abs(d);
		u64 t = now(), late = t > d ? t - d : 0;
		samples[k] = late;
		if (late > max) { max = late; worst = k; }
		sc(SYS_WRITE, kick_disk[1], (i64)"k", 1, 0, 0);
		if (k % SPAM_EVERY == 0) sc(SYS_WRITE, kick_spam[1], (i64)"k", 1, 0, 0);
	}
	sc(SYS_WRITE, kick_disk[1], (i64)"q", 1, 0, 0);
	sc(SYS_WRITE, kick_spam[1], (i64)"q", 1, 0, 0);
	/* Insertion sort is enough for 2000 values. */
	for (int i = 1; i < PERIODS; i++) {
		u64 v = samples[i]; int j = i - 1;
		while (j >= 0 && samples[j] > v) { samples[j + 1] = samples[j]; j--; }
		samples[j + 1] = v;
	}
	u64 spam = 0, dk[2] = { 0, 0 };
	sc(SYS_READ, stat_spam[0], (i64)&spam, 8, 0, 0);
	sc(SYS_READ, stat_disk[0], (i64)dk, 16, 0, 0);
#if defined(__riscv)
	const char *isa = "riscv64";
#else
	const char *isa = "aarch64";
#endif
	p = cat(line, "[LATLX] isa="); p = cat(p, isa);
	p = kv(p, " kernel=linux period_us=", PERIOD_NS / 1000);
	p = kv(p, " periods=", PERIODS);
	p = kv(p, " max_ns=", (i64)max);
	p = kv(p, " p99_ns=", (i64)samples[(PERIODS * 99 + 99) / 100 - 1]);
	p = kv(p, " p50_ns=", (i64)samples[(PERIODS * 50 + 99) / 100 - 1]);
	p = kv(p, " min_ns=", (i64)samples[0]);
	p = kv(p, " worst_period=", worst);
	p = kv(p, " overruns=", (i64)overruns);
	p = kv(p, " sched_fifo_rc=", fifo);
	p = cat(p, "\n");
	sc(SYS_WRITE, 1, (i64)line, p - line, 0, 0);
	p = kv(line, "[LATLX] load spam_lines=", (i64)spam);
	p = kv(p, " disk_reads=", (i64)dk[0]);
	p = kv(p, " disk_errors=", (i64)dk[1]);
	p = cat(p, " hog=1");
	p = kv(p, " devtmpfs_rc=", mnt);
	p = cat(p, "\n");
	sc(SYS_WRITE, 1, (i64)line, p - line, 0, 0);
	puts1("[LATLX] done\n");
	sc(SYS_REBOOT, (i64)0xfee1dead, 672274793, 0x4321fedc, 0, 0);
	for (;;) ;
}

static unsigned char stack[65536] __attribute__((aligned(16), used));
#if defined(__riscv)
__asm__(".globl _start\n_start:\n la sp, stack+65536\n call main_\n");
#else
__asm__(".globl _start\n_start:\n adrp x0, stack+65536\n add x0, x0, :lo12:stack+65536\n mov sp, x0\n bl main_\n");
#endif
