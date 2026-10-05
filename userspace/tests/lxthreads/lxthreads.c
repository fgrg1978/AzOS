/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * LXTHR.ELF: threads under the Linux personality (wave 13, THREADS), a
 * static musl program (`make lxthreads`, zig cc; musl is MIT). It uses
 * pthreads exactly as an unmodified Linux program does: pthread_create (musl
 * maps the stack, clones with CLONE_VM|...|CLONE_SETTLS|CLONE_PARENT_SETTID|
 * CLONE_CHILD_CLEARTID), mutex contention (futex wait/wake), thread-local
 * storage, pthread_join (futex wait on the joined thread's state word; the
 * thread-list lock released by the kernel's clear-tid wake), and one open
 * file description written by two threads. Wave 13: signals across threads
 * (a process-directed signal, a tgkill to a blocked thread, a fatal default
 * action in a threaded child).
 *
 * Every check prints `lxthr: <name> ok` or `lxthr: <name> FAIL`, and the
 * last line is `lxthr: done failures=<n>`.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NT 4
#define ITERS 2000

static __thread int tls_var = 0;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static int fails;
static int shared_fd = -1;
static pid_t thread_tid[NT];

static void check(const char *name, int ok)
{
    printf("lxthr: %s %s\n", name, ok ? "ok" : "FAIL");
    fflush(stdout);
    if (!ok)
        fails++;
}

static void *worker(void *arg)
{
    long id = (long)arg;
    tls_var = (int)id * 100 + 7;
    thread_tid[id - 1] = (pid_t)syscall(SYS_gettid);
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&mu);
        long c = counter;
        /* Give the hart away now and then while holding the lock, so the
         * others find it held and sleep on its futex. */
        if ((i & 63) == 0)
            sched_yield();
        counter = c + 1;
        pthread_mutex_unlock(&mu);
    }
    if (id == 1 && shared_fd >= 0)
        (void)write(shared_fd, "a", 1);
    /* Still this thread's own value after all that switching. */
    return (void *)(long)(tls_var == (int)id * 100 + 7);
}

/* ── Wave 13 (SIGNALS): signals and threads ─────────────────────────────── */

static volatile pid_t usr1_tid;
static volatile int usr2_hits, t_ready, t_go, t_stop, blocked_pending, unblocked_hits;
static volatile pid_t catcher_tid, blocker_tid;

static void on_usr1(int s) { (void)s; usr1_tid = (pid_t)syscall(SYS_gettid); }
static void on_usr2(int s) { (void)s; usr2_hits++; }

static void nap_ms(long ms)
{
    struct timespec d = { 0, ms * 1000000L };
    nanosleep(&d, 0);
}

/* Takes SIGUSR1: the only thread that does not block it. */
static void *catcher(void *a)
{
    (void)a;
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &s, 0);
    catcher_tid = (pid_t)syscall(SYS_gettid);
    __sync_fetch_and_add(&t_ready, 1);
    while (!t_stop)
        nap_ms(2);
    return 0;
}

/* Blocks SIGUSR2: a tgkill aimed at it stays pending on it, and runs its
 * handler here once it unblocks. */
static void *blocker(void *a)
{
    (void)a;
    sigset_t s, p;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &s, 0);
    blocker_tid = (pid_t)syscall(SYS_gettid);
    __sync_fetch_and_add(&t_ready, 1);
    while (!t_go)
        nap_ms(2);
    sigemptyset(&p);
    sigpending(&p);
    blocked_pending = sigismember(&p, SIGUSR2) && usr2_hits == 0;
    pthread_sigmask(SIG_UNBLOCK, &s, 0);
    unblocked_hits = usr2_hits;
    return 0;
}

static void *sleeper(void *a)
{
    (void)a;
    for (;;)
        nap_ms(50);
    return 0;
}

static void signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, 0);
    sa.sa_handler = on_usr2;
    sigaction(SIGUSR2, &sa, 0);
    /* Main blocks SIGUSR1; the threads start with its mask. */
    sigset_t s1;
    sigemptyset(&s1);
    sigaddset(&s1, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &s1, 0);
    pthread_t c, b;
    int ok = pthread_create(&c, 0, catcher, 0) == 0 && pthread_create(&b, 0, blocker, 0) == 0;
    for (int i = 0; i < 1000 && t_ready < 2; i++)
        nap_ms(2);

    /* A process-directed signal goes to a thread that does not block it. */
    kill(getpid(), SIGUSR1);
    for (int i = 0; i < 500 && usr1_tid == 0; i++)
        nap_ms(2);
    printf("lxthr: SIGUSR1 handled by tid %d (catcher %d, main %d)\n", (int)usr1_tid, (int)catcher_tid, (int)getpid());
    check("a process signal lands on an unblocked thread", ok && usr1_tid != 0 && usr1_tid == catcher_tid);

    /* A thread-directed one stays pending on its blocked thread. */
    syscall(SYS_tgkill, getpid(), blocker_tid, SIGUSR2);
    nap_ms(50);
    int before = usr2_hits;
    t_go = 1;
    pthread_join(b, 0);
    printf("lxthr: blocked thread saw pending=%d, hits before %d after %d\n", blocked_pending, before, unblocked_hits);
    check("tgkill to a blocked thread stays pending on it", before == 0 && blocked_pending && unblocked_hits == 1);
    t_stop = 1;
    pthread_join(c, 0);
    pthread_sigmask(SIG_UNBLOCK, &s1, 0);

    /* A fatal default action ends every thread of the process, and the
     * parent's wait sees the child killed by the signal. */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        pthread_t z;
        pthread_create(&z, 0, sleeper, 0);
        nap_ms(20);
        kill(getpid(), SIGTERM);
        nap_ms(2000);
        _exit(3);
    }
    int st = 0;
    pid_t w = waitpid(pid, &st, 0);
    printf("lxthr: threaded child status 0x%x\n", st);
    check("a fatal signal ends every thread; wait sees WIFSIGNALED",
          w == pid && WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
}

int main(void)
{
    pthread_t t[NT];
    int created = 0, joined = 0, tls_ok = 1;
    tls_var = 1;
    shared_fd = open("/tmp/LXT", O_RDWR | O_CREAT | O_TRUNC, 0644);
    check("open /tmp/LXT", shared_fd >= 0);

    int err = 0;
    for (long i = 0; i < NT; i++) {
        int e = pthread_create(&t[i], 0, worker, (void *)(i + 1));
        if (e == 0)
            created++;
        else if (!err)
            err = e;
    }
    if (err)
        printf("lxthr: pthread_create answered %d (%s)\n", err, strerror(err));
    check("pthread_create x4", created == NT);
    for (int i = 0; i < created; i++) {
        void *r = 0;
        if (pthread_join(t[i], &r) == 0) {
            joined++;
            tls_ok &= (long)r == 1;
        }
    }
    check("pthread_join x4", joined == NT);
    check("mutex contention keeps the count exact", counter == (long)NT * ITERS);
    check("tls distinct per thread", tls_ok && tls_var == 1);

    pid_t me = getpid();
    int distinct = 1;
    for (int i = 0; i < NT; i++)
        distinct &= thread_tid[i] > 0 && thread_tid[i] != me;
    check("gettid differs from getpid in a thread", distinct && syscall(SYS_gettid) == me);

    if (shared_fd >= 0) {
        (void)write(shared_fd, "b", 1);
        char buf[4] = {0};
        (void)lseek(shared_fd, 0, SEEK_SET);
        long n = read(shared_fd, buf, sizeof buf);
        printf("lxthr: shared file reads [%.*s]\n", n > 0 ? (int)n : 0, buf);
        check("a thread and main write one open file description", n == 2 && memcmp(buf, "ab", 2) == 0);
        close(shared_fd);
    }

    /* A second round after the first joined: threads are created and torn
     * down again in the same address space. */
    counter = 0;
    created = joined = 0;
    for (long i = 0; i < 2; i++)
        if (pthread_create(&t[i], 0, worker, (void *)(i + 2)) == 0)
            created++;
    for (int i = 0; i < created; i++)
        if (pthread_join(t[i], 0) == 0)
            joined++;
    check("a second round of threads", created == 2 && joined == 2 && counter == 2L * ITERS);

    signals();

    printf("lxthr: done failures=%d\n", fails);
    fflush(stdout);
    return fails != 0;
}
