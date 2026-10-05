// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// LXTEST.KO: the module the RFC-0053 L0b loader rows load. Our own code, not
// Linux code, and it includes no Linux header: it exists so that the loader,
// SYS_MODULE_VERIFY and the token-gated SYS_MODULE_MAP_X are exercised end to
// end before any GPL object enters an image (stage L1 needs the owner's
// sign-off first).
//
// It is compiled `-c` into a relocatable object (ET_REL), exactly the shape
// of a Linux `.ko`, and is chosen to carry the relocation kinds a Linux
// module carries on each ISA: calls into the server's exported symbols, PC-
// relative references to its own .data/.bss/.rodata, absolute 64-bit
// pointers in a .data table, and branches within .text.
//
// `lxtest_init` returns a value the server recomputes independently, so a
// relocation that resolves to the wrong address changes the number instead of
// passing quietly.

typedef unsigned long u64;
typedef unsigned int u32;

// Exported by the server (lxsrv's symbol table). Resolved by the loader.
extern void lx_test_log(const char *msg);
extern u64 lx_test_mix(u64 acc, u64 v);

#define MODINFO(tag, val) \
    static const char __modinfo_##tag[] \
    __attribute__((section(".modinfo"), used, aligned(1))) = #tag "=" val

MODINFO(license, "Dual Apache/GPL");
MODINFO(vermagic, "azos-lx0");
MODINFO(name, "lxtest");

static const char banner[] = "lxtest: init running";

// .data: absolute pointers (R_RISCV_64 / R_AARCH64_ABS64) to .rodata, .data
// and .text.
static u64 counter = 7;
u64 lxtest_scratch[4];                  // .bss (global: kept, and visible to the loader's symbol table)
static u64 step(u64 x);
// Not const: a table the compiler cannot fold, so the pointers stay in .data
// as absolute relocations the loader must apply.
static const char *strings[] = { banner, "lxtest: second string" };
static u64 (*steps[])(u64) = { step };
static volatile u32 pick;              // .bss, read at run time: defeats folding

static __attribute__((noinline)) u64 step(u64 x)
{
    // A loop: in-function branches (B/BEQ/CBZ, R_RISCV_BRANCH when not
    // resolved by the assembler).
    u64 acc = x;
    for (u32 i = 0; i < 5; i++) {
        if (acc & 1)
            acc = acc * 3 + 1;
        else
            acc >>= 1;
    }
    return acc;
}

u64 lxtest_init(void)
{
    lx_test_log(strings[pick]);
    u64 acc = 0x4c58;                   // "LX"
    acc = lx_test_mix(acc, counter);
    counter += 1;
    for (u32 i = 0; i < 4; i++) {
        lxtest_scratch[i] = steps[pick](acc + i);
        acc = lx_test_mix(acc, lxtest_scratch[i]);
    }
    acc = lx_test_mix(acc, (u64)strings[1][0]);
    acc = lx_test_mix(acc, counter);
    lx_test_log(strings[1]);
    return acc;
}
