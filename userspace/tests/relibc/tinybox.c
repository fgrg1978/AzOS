/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/* A multi-call toolbox of small shell utilities on relibc, the C program that
 * exercises the platform layer: stdio over files and the console, directories,
 * posix_spawn and waitpid, pthreads (futex, TLS, thread stacks), the clock and
 * the environment.
 *
 *   tinybox cat FILE...      copy files to the console
 *   tinybox wc FILE...       lines, words and bytes
 *   tinybox ls [DIR]         names, sizes and types
 *   tinybox mkdir DIR...     / rm FILE... / rmdir DIR...
 *   tinybox pwd | env | uname
 *   tinybox run PROG [ARG..] spawn PROG, wait for it, print its status
 *   tinybox threads [N]      N threads (default 4) bump a counter under a mutex
 *   tinybox sleep MS         sleep, and print how long it really took
 *
 * The program name selects the tool too: `cat file` when started as "cat". */
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static int fail(const char *what, const char *arg)
{
    fprintf(stderr, "tinybox: %s %s: %s\n", what, arg ? arg : "", strerror(errno));
    return 1;
}

static int do_cat(int argc, char **argv)
{
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        if (!f) { rc = fail("cat", argv[i]); continue; }
        char buf[512];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0)
            fwrite(buf, 1, n, stdout);
        fclose(f);
    }
    return rc;
}

static int do_wc(int argc, char **argv)
{
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        if (!f) { rc = fail("wc", argv[i]); continue; }
        unsigned long lines = 0, words = 0, bytes = 0;
        int c, in_word = 0;
        while ((c = fgetc(f)) != EOF) {
            bytes++;
            if (c == '\n') lines++;
            if (c == ' ' || c == '\n' || c == '\t') in_word = 0;
            else if (!in_word) { in_word = 1; words++; }
        }
        fclose(f);
        printf("%lu %lu %lu %s\n", lines, words, bytes, argv[i]);
    }
    return rc;
}

static int do_ls(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    DIR *d = opendir(dir);
    if (!d) return fail("ls", dir);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char path[256];
        struct stat st;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (stat(path, &st) == 0)
            printf("%c %8lu %s\n", S_ISDIR(st.st_mode) ? 'd' : '-', (unsigned long)st.st_size, e->d_name);
        else
            printf("? %8s %s\n", "-", e->d_name);
    }
    closedir(d);
    return 0;
}

static int do_each(int argc, char **argv, int (*op)(const char *), const char *name)
{
    int rc = 0;
    for (int i = 1; i < argc; i++)
        if (op(argv[i]) != 0) rc = fail(name, argv[i]);
    return rc;
}

static int op_mkdir(const char *p) { return mkdir(p, 0755); }

static int do_pwd(void)
{
    char buf[256];
    if (!getcwd(buf, sizeof buf)) return fail("pwd", NULL);
    puts(buf);
    return 0;
}

static int do_env(void)
{
    for (char **e = environ; e && *e; e++) puts(*e);
    return 0;
}

static int do_uname(void)
{
    struct utsname u;
    if (uname(&u) != 0) return fail("uname", NULL);
    printf("%s %s %s %s %s\n", u.sysname, u.nodename, u.release, u.version, u.machine);
    return 0;
}

static int do_run(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: tinybox run PROG [ARG..]\n"); return 2; }
    pid_t pid;
    int err = posix_spawn(&pid, argv[1], NULL, NULL, &argv[1], environ);
    if (err) { errno = err; return fail("run", argv[1]); }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return fail("wait", argv[1]);
    if (WIFEXITED(status))
        printf("%s exited with %d\n", argv[1], WEXITSTATUS(status));
    else
        printf("%s was killed by signal %d\n", argv[1], WTERMSIG(status));
    return 0;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long counter;
static __thread unsigned long per_thread;   /* TLS: each thread sees its own */

static void *bump(void *arg)
{
    unsigned long n = (unsigned long)arg;
    for (unsigned long i = 0; i < n; i++) {
        per_thread++;
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return (void *)per_thread;
}

static int do_threads(int argc, char **argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 4;
    pthread_t t[8];
    if (n < 1 || n > 8) { fprintf(stderr, "tinybox threads: 1..8\n"); return 2; }
    for (int i = 0; i < n; i++)
        if (pthread_create(&t[i], NULL, bump, (void *)1000UL) != 0) return fail("threads", "create");
    int ok = 1;
    for (int i = 0; i < n; i++) {
        void *ret;
        pthread_join(t[i], &ret);
        if ((unsigned long)ret != 1000UL) ok = 0;
    }
    printf("threads: counter=%lu (want %lu), per-thread TLS %s, main TLS=%lu\n",
           counter, 1000UL * (unsigned long)n, ok ? "ok" : "WRONG", per_thread);
    return counter == 1000UL * (unsigned long)n && ok ? 0 : 1;
}

static int do_sleep(int argc, char **argv)
{
    long ms = argc > 1 ? atol(argv[1]) : 10;
    struct timespec a, b, rq = { ms / 1000, (ms % 1000) * 1000000L };
    clock_gettime(CLOCK_MONOTONIC, &a);
    nanosleep(&rq, NULL);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long took = (long)((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000);
    printf("slept %ld ms (asked %ld)\n", took, ms);
    return took >= ms ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *name = strrchr(argv[0], '/');
    name = name ? name + 1 : argv[0];
    if (strcmp(name, "tinybox") == 0 || strncmp(name, "TINYBOX", 7) == 0) {
        if (argc < 2) { fprintf(stderr, "usage: tinybox TOOL [ARG..]\n"); return 2; }
        argc--; argv++;
        name = argv[0];
    }
    if (!strcmp(name, "cat")) return do_cat(argc, argv);
    if (!strcmp(name, "wc")) return do_wc(argc, argv);
    if (!strcmp(name, "ls")) return do_ls(argc, argv);
    if (!strcmp(name, "mkdir")) return do_each(argc, argv, op_mkdir, "mkdir");
    if (!strcmp(name, "rm")) return do_each(argc, argv, unlink, "rm");
    if (!strcmp(name, "rmdir")) return do_each(argc, argv, rmdir, "rmdir");
    if (!strcmp(name, "pwd")) return do_pwd();
    if (!strcmp(name, "env")) return do_env();
    if (!strcmp(name, "uname")) return do_uname();
    if (!strcmp(name, "run")) return do_run(argc, argv);
    if (!strcmp(name, "threads")) return do_threads(argc, argv);
    if (!strcmp(name, "sleep")) return do_sleep(argc, argv);
    fprintf(stderr, "tinybox: unknown tool '%s'\n", name);
    return 2;
}
