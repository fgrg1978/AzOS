// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/*
 * lxbase.ko: the base of the lx/ layer at stage L1 (RFC-0053 4.2-4.4).
 *
 * It is compiled by Linux's own Kbuild against the pinned tree, so every
 * prototype, gfp flag and array shape below comes from the Linux headers of
 * that tree and the configuration the modules are built with; a mismatch is
 * a compile error, not a silent ABI drift. That is why this file is
 * GPL-2.0-only and why it is only ever shipped inside a .ko (RFC-0053 10.2):
 * no AzOS image links it.
 *
 * It exports exactly the Linux symbols the validated modules import (the
 * RFC 5.1 rule: build the module, take `nm -u`, implement that set) and
 * forwards them to the host ABI below, which the Linux driver server
 * (userspace/services/lxsrv, Apache-2.0 OR GPL-2.0-only, no Linux header)
 * provides. The host ABI is plain scalars and pointers, no Linux type, and
 * is listed in lx/HOST_ABI, which tools/lx_license_lint.py
 * enforces against every .ko's imports.
 */
#include <linux/crc32.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

/* Host ABI (lxsrv). lxh_alloc returns zeroed memory aligned to `align`
 * (a power of two, at most PAGE_SIZE) or NULL; lxh_free takes what
 * lxh_alloc returned. */
extern void *lxh_alloc(size_t size, size_t align);
extern void lxh_free(const void *p);
/* The kernel's vDSO hwcap word (crates/core/abi/src/vdso.rs). */
extern u64 lxh_hwcap(void);
#define LXH_HWCAP_A64_CRC32	(1ULL << 0)
#define LXH_HWCAP_RV_ZBC	(1ULL << 33)

/*
 * Inline kmalloc() indexes this table with constants from slab.h and passes
 * the entry to __kmalloc_cache_noprof() with the size, which is all the
 * host allocator needs: the entries stay NULL.
 */
kmem_buckets kmalloc_caches[NR_KMALLOC_TYPES];
EXPORT_SYMBOL(kmalloc_caches);

static void *lx_kmalloc(size_t size, gfp_t flags)
{
	size_t align = ARCH_KMALLOC_MINALIGN;
	void *p;

	if (!size)
		return ZERO_SIZE_PTR;
	/* kmalloc() aligns power-of-two sizes naturally, up to a page. */
	if (is_power_of_2(size))
		align = max_t(size_t, align, min_t(size_t, size, PAGE_SIZE));
	p = lxh_alloc(size, align);
	if (p && (flags & __GFP_ZERO))
		memset(p, 0, size);
	return p;
}

void *__kmalloc_noprof(DECL_TOKEN_PARAMS(size, token), gfp_t flags)
{
	return lx_kmalloc(size, flags);
}
EXPORT_SYMBOL(__kmalloc_noprof);

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t flags, size_t size)
{
	return lx_kmalloc(size, flags);
}
EXPORT_SYMBOL(__kmalloc_cache_noprof);

void *__kmalloc_large_noprof(size_t size, gfp_t flags)
{
	void *p = lxh_alloc(size, PAGE_SIZE);

	if (p && (flags & __GFP_ZERO))
		memset(p, 0, size);
	return p;
}
EXPORT_SYMBOL(__kmalloc_large_noprof);

void kfree(const void *p)
{
	if (!ZERO_OR_NULL_PTR(p))
		lxh_free(p);
}
EXPORT_SYMBOL(kfree);

void *vmalloc_noprof(unsigned long size)
{
	return size ? lxh_alloc(size, PAGE_SIZE) : NULL;
}
EXPORT_SYMBOL(vmalloc_noprof);

void vfree(const void *p)
{
	if (p)
		lxh_free(p);
}
EXPORT_SYMBOL(vfree);

/*
 * IEEE CRC-32, LSB first, no pre/post inversion: the contract of crc32_le()
 * in <linux/crc32.h>. xz_dec checks every decoded byte with it.
 *
 * Two implementations, chosen once by this module's init from the kernel's
 * hwcap word (never from build flags):
 *  - aarch64 with FEAT_CRC32: the CRC32X/B instructions, 64 bytes per
 *    loop step;
 *  - riscv64 with Zbc: carry-less multiply, 8 bytes per three `clmulr`;
 *  - otherwise slice-by-8 (eight 1 KiB tables built by init). The first
 *    version, a bitwise loop, was two thirds of the whole decode.
 * lxbase_crc32_impl says which one runs (0 = tables, 1 = arm64 CRC32,
 * 2 = riscv64 Zbc), and
 * the server prints it.
 */
static u32 crc32_tab[8][256];
int lxbase_crc32_impl;
EXPORT_SYMBOL(lxbase_crc32_impl);

static u32 crc32_le_tables(u32 crc, const u8 *b, size_t len)
{
	u64 v;

	for (; len && ((unsigned long)b & 7); len--)
		crc = (crc >> 8) ^ crc32_tab[0][(crc ^ *b++) & 0xff];
	for (; len >= 8; len -= 8, b += 8) {
		v = *(const u64 *)b ^ crc;	/* both ISAs are little-endian */
		crc = crc32_tab[7][v & 0xff] ^ crc32_tab[6][(v >> 8) & 0xff] ^
		      crc32_tab[5][(v >> 16) & 0xff] ^ crc32_tab[4][(v >> 24) & 0xff] ^
		      crc32_tab[3][(v >> 32) & 0xff] ^ crc32_tab[2][(v >> 40) & 0xff] ^
		      crc32_tab[1][(v >> 48) & 0xff] ^ crc32_tab[0][v >> 56];
	}
	for (; len; len--)
		crc = (crc >> 8) ^ crc32_tab[0][(crc ^ *b++) & 0xff];
	return crc;
}

#ifdef CONFIG_ARM64
static u32 crc32_le_arm64(u32 crc, const u8 *b, size_t len)
{
	u64 x0, x1, x2, x3;

	for (; len && ((unsigned long)b & 7); len--)
		asm(".arch_extension crc\n\tcrc32b %w0, %w0, %w1" : "+r"(crc) : "r"((u32)*b++));
	for (; len >= 64; len -= 64, b += 64) {
		const u64 *q = (const u64 *)b;

		x0 = q[0]; x1 = q[1]; x2 = q[2]; x3 = q[3];
		asm(".arch_extension crc\n\t"
		    "crc32x %w0, %w0, %x1\n\tcrc32x %w0, %w0, %x2\n\t"
		    "crc32x %w0, %w0, %x3\n\tcrc32x %w0, %w0, %x4"
		    : "+r"(crc) : "r"(x0), "r"(x1), "r"(x2), "r"(x3));
		x0 = q[4]; x1 = q[5]; x2 = q[6]; x3 = q[7];
		asm(".arch_extension crc\n\t"
		    "crc32x %w0, %w0, %x1\n\tcrc32x %w0, %w0, %x2\n\t"
		    "crc32x %w0, %w0, %x3\n\tcrc32x %w0, %w0, %x4"
		    : "+r"(crc) : "r"(x0), "r"(x1), "r"(x2), "r"(x3));
	}
	for (; len >= 8; len -= 8, b += 8)
		asm(".arch_extension crc\n\tcrc32x %w0, %w0, %x1" : "+r"(crc) : "r"(*(const u64 *)b));
	for (; len; len--)
		asm(".arch_extension crc\n\tcrc32b %w0, %w0, %w1" : "+r"(crc) : "r"((u32)*b++));
	return crc;
}
#endif

#ifdef CONFIG_RISCV
/*
 * riscv64 with Zbc: the bit-reflected domain `clmulr` exists for. A 64-bit
 * accumulator is folded forward one word at a time (two `clmulr`), and only
 * the end reduces to 32 bits: (a * z^32) mod P by folding the high half
 * with z^64 mod P and a Barrett step with MU = floor(z^64 / P). Constants
 * are z^64 mod P, z^96 mod P, MU and P, bit-reversed in 64 bits; derived
 * and checked against the table CRC by tools/lx_kbuild/zbc_crc_constants.py,
 * and checked again by lxbase_init on the running hart before use.
 */
static inline u64 clmulr(u64 a, u64 b)
{
	u64 r;

	asm(".option push\n\t.option arch, +zbc\n\tclmulr %0, %1, %2\n\t.option pop"
	    : "=r"(r) : "r"(a), "r"(b));
	return r;
}

static inline u64 clmul(u64 a, u64 b)
{
	u64 r;

	asm(".option push\n\t.option arch, +zbc\n\tclmul %0, %1, %2\n\t.option pop"
	    : "=r"(r) : "r"(a), "r"(b));
	return r;
}

static inline u64 clmulh(u64 a, u64 b)
{
	u64 r;

	asm(".option push\n\t.option arch, +zbc\n\tclmulh %0, %1, %2\n\t.option pop"
	    : "=r"(r) : "r"(a), "r"(b));
	return r;
}

/* The 128-bit accumulator (h, l) folded forward over the next 16 bytes:
 * h*z^192 + l*z^128 with constants rev64(z^191 mod P), rev64(z^127 mod P),
 * whose full 128-bit carry-less products land already split into the two
 * accumulator words (clmul = the low one, clmulh = the high one). */
#define ZBC_C128	0x9ba54c6f00000000ULL
#define ZBC_C192	0x65673b4600000000ULL

/* The 64-bit accumulator a (reflected) folded forward over one more word:
 * a*z^64 = a_h*(z^96 mod P) + a_l*(z^64 mod P), two `clmulr`. */
#define ZBC_K64R	0xb1e6b09200000000ULL
#define ZBC_K96R	0x6655004f00000000ULL
#define ZBC_MUR		0xfb808b2080000000ULL
#define ZBC_PR		0xedb8832080000000ULL
#define ZBC_FOLD(a, w) ((w) ^ clmulr((a) << 32, ZBC_K96R) ^ clmulr((a) & 0xffffffff00000000ULL, ZBC_K64R))

static u32 crc32_le_zbc(u32 crc, const u8 *b, size_t len)
{
	const u64 *w;
	u64 a, y, q;
	size_t n;

	for (; len && ((unsigned long)b & 7); len--)
		crc = (crc >> 8) ^ crc32_tab[0][(crc ^ *b++) & 0xff];
	if (len >= 8) {
		w = (const u64 *)b;
		n = len / 8;
		a = crc ^ *w++;
		n--;
		if (n >= 1) {
			u64 h = a, l = *w++, nh;

			n--;
			for (; n >= 4; n -= 4, w += 4) {
				nh = w[0] ^ clmul(h, ZBC_C192) ^ clmul(l, ZBC_C128);
				l = w[1] ^ clmulh(h, ZBC_C192) ^ clmulh(l, ZBC_C128);
				h = nh;
				nh = w[2] ^ clmul(h, ZBC_C192) ^ clmul(l, ZBC_C128);
				l = w[3] ^ clmulh(h, ZBC_C192) ^ clmulh(l, ZBC_C128);
				h = nh;
			}
			a = ZBC_FOLD(h, l);
		}
		for (; n; n--)
			a = ZBC_FOLD(a, *w++);
		/* (a * z^32) mod P: fold the high half, then Barrett. */
		y = clmulr(a << 32, ZBC_K64R) ^ (a >> 32);
		q = clmulr(y << 32, ZBC_MUR) << 32;
		crc = (y ^ clmulr(q, ZBC_PR)) >> 32;
		b = (const u8 *)w;
		len &= 7;
	}
	for (; len; len--)
		crc = (crc >> 8) ^ crc32_tab[0][(crc ^ *b++) & 0xff];
	return crc;
}
#endif

static int __init lxbase_init(void)
{
	u32 c;
	int i, k;

	for (i = 0; i < 256; i++) {
		c = i;
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320 & -(c & 1));
		crc32_tab[0][i] = c;
	}
	for (i = 0; i < 256; i++)
		for (k = 1; k < 8; k++)
			crc32_tab[k][i] = (crc32_tab[k - 1][i] >> 8) ^ crc32_tab[0][crc32_tab[k - 1][i] & 0xff];
#ifdef CONFIG_ARM64
	if (lxh_hwcap() & LXH_HWCAP_A64_CRC32) {
		/* Trust, but check against the tables once (CRC-32 of "123456789"
		 * is 0xcbf43926 with the usual inversions). */
		static const u8 check[9] = "123456789";

		if ((~crc32_le_arm64(~0U, check, 9)) == 0xcbf43926 &&
		    (~crc32_le_tables(~0U, check, 9)) == 0xcbf43926)
			lxbase_crc32_impl = 1;
	}
#endif
#ifdef CONFIG_RISCV
	if (lxh_hwcap() & LXH_HWCAP_RV_ZBC) {
		static const u8 check[9] = "123456789";
		u8 buf[64];
		int j;

		/* The known answer, and a multi-word buffer against the tables. */
		for (j = 0; j < 64; j++)
			buf[j] = (u8)(j * 37 + 11);
		if ((~crc32_le_zbc(~0U, check, 9)) == 0xcbf43926 &&
		    crc32_le_zbc(0x12345678, buf + 3, 57) == crc32_le_tables(0x12345678, buf + 3, 57))
			lxbase_crc32_impl = 2;
	}
#endif
	return 0;
}
module_init(lxbase_init);

u32 crc32_le(u32 crc, const void *p, size_t len)
{
#ifdef CONFIG_ARM64
	if (lxbase_crc32_impl == 1)
		return crc32_le_arm64(crc, p, len);
#endif
#ifdef CONFIG_RISCV
	if (lxbase_crc32_impl == 2)
		return crc32_le_zbc(crc, p, len);
#endif
	return crc32_le_tables(crc, p, len);
}
EXPORT_SYMBOL(crc32_le);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AzOS lx/ base: Linux allocator and CRC symbols over the lxsrv host ABI");
