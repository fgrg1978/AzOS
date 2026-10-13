// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/*
 * lxbench.ko: the Linux side of the L1 comparison (RFC-0053; owner rule,
 * wave 13: report against Linux on the same QEMU). Loaded by the comparison
 * initramfs's /init into a Linux kernel built from the pinned tree with the
 * same configuration as the AzOS modules, after the very same xz_dec.ko.
 * Its init does, in kernel, exactly what the AzOS Linux driver server
 * times: xz_dec_init(XZ_SINGLE) + xz_dec_run over XZTEST.XZ + xz_dec_end,
 * read with the same counter (riscv `time`, aarch64 `cntvct_el0`).
 * It is never put on a AzOS volume.
 */
#include <linux/crc32.h>
#include <linux/kernel_read_file.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/timex.h>
#include <linux/vmalloc.h>
#include <linux/xz.h>

static u64 counter(void)
{
#ifdef CONFIG_RISCV
	return csr_read(CSR_TIME);
#else
	isb();
	return read_sysreg(cntvct_el0);
#endif
}

static int __init lxbench_init(void)
{
	void *in = NULL;
	size_t size = 0;
	ssize_t n;
	struct xz_buf b;
	struct xz_dec *s;
	enum xz_ret ret = XZ_MEM_ERROR;
	u32 c;
	u8 *out;
	u64 t0, t1;
	int i;

	n = kernel_read_file_from_path("/XZTEST.XZ", 0, &in, INT_MAX, &size, READING_UNKNOWN);
	if (n < 0) {
		pr_err("lxbench: cannot read /XZTEST.XZ: %zd\n", n);
		return n;
	}
	out = vmalloc(49152 + 4096);
	if (!out) {
		vfree(in);
		return -ENOMEM;
	}
	/* Twice, as the AzOS server does (its first decode also takes the
	 * first-touch faults of demand-paged memory; here both are warm). */
	for (i = 0; i < 2; i++) {
		t0 = counter();
		s = xz_dec_init(XZ_SINGLE, 0);
		b.in = in;
		b.in_pos = 0;
		b.in_size = n;
		b.out = out;
		b.out_pos = 0;
		b.out_size = 49152 + 4096;
		if (s) {
			ret = xz_dec_run(s, &b);
			xz_dec_end(s);
		}
		t1 = counter();
		pr_info("lxbench: xz decode %d: %zd -> %zu bytes, ret %d, ticks %llu\n", i, n, b.out_pos, ret, t1 - t0);
	}
	t0 = counter();
	c = crc32_le(~0U, out, 49152);
	t1 = counter();
	pr_info("lxbench: crc32_le 48K ticks %llu (%08x)\n", t1 - t0, c);
	vfree(out);
	vfree(in);
	return 0;
}
module_init(lxbench_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AzOS L1 comparison: in-kernel xz_dec decode timing");
