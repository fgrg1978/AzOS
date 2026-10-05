// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/*
 * /init of the Linux comparison initramfs (RFC-0053 L1; tools/lx_kbuild/run.sh
 * linux). Static, no C library, no Linux header: raw syscalls of the generic
 * table riscv64 and aarch64 share. It times `init_module` of the same
 * xz_dec.ko the AzOS server loads (file already in memory on both sides),
 * then loads lxbench.ko, whose init times the in-kernel decode; and the null
 * syscall, the floor of any request a client would make to a driver.
 * Counter: riscv `time` (10 MHz on QEMU virt), aarch64 `cntvct_el0`
 * (frequency printed); under -icount shift=0 one virtual ns is one
 * instruction.
 */
typedef unsigned long u64;

static long sc(long n, long a, long b, long c, long d)
{
#if defined(__riscv)
	register long a0 __asm__("a0") = a, a1 __asm__("a1") = b, a2 __asm__("a2") = c, a3 __asm__("a3") = d;
	register long a7 __asm__("a7") = n;
	__asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a7) : "memory");
	return a0;
#else
	register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c, x3 __asm__("x3") = d;
	register long x8 __asm__("x8") = n;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
	return x0;
#endif
}

enum { SYS_OPENAT = 56, SYS_READ = 63, SYS_WRITE = 64, SYS_EXIT = 93, SYS_GETPPID = 173, SYS_INIT_MODULE = 105 };

static u64 counter(void)
{
	u64 t;
#if defined(__riscv)
	__asm__ volatile("rdtime %0" : "=r"(t));
#else
	__asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(t));
#endif
	return t;
}

static u64 freq(void)
{
#if defined(__riscv)
	return 10000000;
#else
	u64 f;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
	return f;
#endif
}

static void put(const char *s)
{
	long n = 0;
	while (s[n])
		n++;
	sc(SYS_WRITE, 1, (long)s, n, 0);
}

static void putu(u64 v)
{
	char b[24];
	int i = 23;
	b[i] = 0;
	do {
		b[--i] = '0' + v % 10;
		v /= 10;
	} while (v);
	put(b + i);
}

static void puti(long v)
{
	if (v < 0) {
		put("-");
		v = -v;
	}
	putu(v);
}

static char buf[256 * 1024];

static long load(const char *path)
{
	long fd = sc(SYS_OPENAT, -100, (long)path, 0, 0), n = 0, r;
	if (fd < 0)
		return fd;
	while ((r = sc(SYS_READ, fd, (long)buf + n, sizeof(buf) - n, 0)) > 0)
		n += r;
	return n;
}

static void insmod(const char *path, const char *name)
{
	long n = load(path), rc;
	u64 t0, t1;
	if (n <= 0) {
		put("lxbench: cannot read ");
		put(path);
		put("\n");
		return;
	}
	t0 = counter();
	rc = sc(SYS_INIT_MODULE, (long)buf, n, (long)"", 0);
	t1 = counter();
	put("lxbench: init_module ");
	put(name);
	put(" bytes ");
	putu(n);
	put(" rc ");
	puti(rc);
	put(" ticks ");
	putu(t1 - t0);
	put("\n");
}

void _start(void)
{
	u64 t0, t1;
	int i;
	put("lxbench: counter hz ");
	putu(freq());
	put("\n");
	insmod("/xz_dec.ko", "xz_dec.ko");
	insmod("/lxbench.ko", "lxbench.ko");
	t0 = counter();
	for (i = 0; i < 1000; i++)
		sc(SYS_GETPPID, 0, 0, 0, 0);
	t1 = counter();
	put("lxbench: getppid x1000 ticks ");
	putu(t1 - t0);
	/* The AzOS server's calibration loop: 2 x 4,000,000 instructions. */
	t0 = counter();
#if defined(__riscv)
	__asm__ volatile("li t0, 4000000\n1: addi t0, t0, -1\n bnez t0, 1b" ::: "t0");
#else
	__asm__ volatile("movz x9, #0x3d, lsl #16\n movk x9, #0x0900\n1: subs x9, x9, #1\n b.ne 1b" ::: "x9", "cc");
#endif
	t1 = counter();
	put("\nlxbench: 8M-instruction loop ticks ");
	putu(t1 - t0);
	put("\nlxbench: done\n");
	for (;;)
		sc(SYS_READ, 0, (long)buf, 1, 0);
}
