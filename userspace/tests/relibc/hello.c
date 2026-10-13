/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* The C hello world on relibc: the smallest program that needs the whole
 * startup (the entry, the TLS block, the allocator, stdio over the console). */
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("Hello from C on AzOS (relibc), argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("  argv[%d] = %s\n", i, argv[i]);
    return 0;
}
