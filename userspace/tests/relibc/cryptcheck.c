/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* crypt() and crypt_r() fail as NULL, never as a string: an unknown method, and a hash
 * longer than crypt_data's buffer, are refused; a password of any length hashes; the
 * crypt_r result lives in the caller's crypt_data. Exit 0 when every check holds. */
#include <crypt.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what)
{
    if (!ok) {
        printf("cryptcheck FAIL %s\n", what);
        fails++;
    }
}

int main(void)
{
    static char pw[16384];
    static char setting[512];
    crypt_data data = { 0 };

    char *h = crypt("secret", "$6$saltsalt$");
    check(h && strncmp(h, "$6$saltsalt$", 12) == 0, "sha512 hashes");
    check(crypt("secret", "$9$x$") == NULL, "unknown method is NULL");
    check(crypt("secret", "xx") == NULL, "DES is NULL");

    for (size_t len = 0; len <= sizeof pw - 1; len = len ? len * 4 : 1) {
        memset(pw, 'a', len);
        pw[len] = 0;
        h = crypt_r(pw, "$6$saltsalt$", &data);
        check(h != NULL && strlen(h) < 256, "a password of any length hashes");
        check(h >= (char *)&data && h < (char *)&data + sizeof data, "result is in crypt_data");
    }

    memset(setting, 0, sizeof setting);
    strcpy(setting, "$argon2id$v=19$m=8,t=1,p=1$");
    memset(setting + strlen(setting), 'A', 300);
    errno = 0;
    h = crypt_r("secret", setting, &data);
    check(h == NULL, "a hash longer than the buffer is NULL");

    printf("cryptcheck: %s\n", fails ? "FAIL" : "ok");
    return fails != 0;
}
