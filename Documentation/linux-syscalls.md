<!-- Generated from crates/core/linux-abi/src/table.rs by tests/host/linux-abi-tests (table_drift::the_document_is_the_table); do not edit by hand. -->

# Linux calls the personality answers

One row per Linux call (asm-generic numbers, riscv64 and aarch64; the x86-64 face translates to these). A call not listed answers `-ENOSYS` and is counted per number (`azos_linux_abi::tally`), so the next call to add is the one a real binary asked for.

Class: `needed` is answered in full for what the measured binaries ask of it; `deferred` is answered in a reduced shape and waits for the tally; `never` is refused by design.

| Number | Call | Class | Native calls reached | Note |
|---:|---|---|---|---|
| 17 | `getcwd` | needed | none | From the personality's own state: the working directory it keeps per process. |
| 23 | `dup` | needed | none | A descriptor alias in the personality's table; no native call. |
| 24 | `dup3` | needed | `SYS_CAP_CLOSE` | `dup3` onto an open descriptor closes it first. |
| 25 | `fcntl` | deferred | none | Descriptor flags and `F_DUPFD` over the personality's table. |
| 29 | `ioctl` | deferred | none | The console's terminal requests only. |
| 49 | `chdir` | needed | `SYS_INVOKE` | A directory is recognised with `stat`, or by listing for a mount point the VFS cannot stat. |
| 56 | `openat` | needed | `SYS_INVOKE`, `SYS_CAP_CLOSE` | A file is opened through `Cap<File>` and closed again when no descriptor is left for it; a directory is read later with `readdir`. |
| 57 | `close` | needed | `SYS_CAP_CLOSE` | Releases the handle when no descriptor is left for it. |
| 59 | `pipe2` | needed | `SYS_MO_CREATE`, `SYS_CAP_CLOSE` | The pipe is a memory object with a byte ring in it, closed again when no descriptor is left for it. |
| 61 | `getdents64` | needed | `SYS_INVOKE` | Asks the covering tree again on every call. |
| 62 | `lseek` | needed | `SYS_INVOKE` | The offset of the open file description, over a held `Cap<File>`; the file is reached through `SYS_INVOKE`. |
| 63 | `read` | needed | `SYS_INVOKE` | The console reads through the input the shell lent its foreground job. |
| 64 | `write` | needed | `SYS_INVOKE` |  |
| 65 | `readv` | needed | `SYS_INVOKE` |  |
| 66 | `writev` | needed | `SYS_INVOKE` |  |
| 73 | `ppoll` | deferred | `SYS_SLEEP_UNTIL` | Answered only by the ring-3 runtime; the in-kernel table answers `-ENOSYS` and tallies it. |
| 79 | `newfstatat` | needed | `SYS_INVOKE` |  |
| 80 | `fstat` | needed | `SYS_INVOKE` | A file's size is read through its held `Cap<File>`; a directory descriptor is stat'ed by its path. |
| 93 | `exit` | needed | `SYS_EXIT`, `SYS_THREAD_EXIT` | A thread's exit; the last thread ends the process. |
| 94 | `exit_group` | needed | `SYS_EXIT` |  |
| 96 | `set_tid_address` | needed | none | The word the calling thread's exit clears and wakes. |
| 98 | `futex` | deferred | `SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE` | `FUTEX_WAIT`/`FUTEX_WAKE` and their `_BITSET` forms with a full mask, private to the process; requeue reaches the wake. |
| 99 | `set_robust_list` | needed | none | The robust futex list walked at the thread's exit. |
| 101 | `nanosleep` | needed | `SYS_SLEEP_UNTIL` |  |
| 113 | `clock_gettime` | deferred | none | Read from the vDSO clock; no native call. |
| 123 | `sched_getaffinity` | deferred | none | One CPU, the one the task runs on; another task's is answered only when the caller may signal it. |
| 124 | `sched_yield` | needed | `SYS_YIELD` |  |
| 129 | `kill` | needed | `SYS_ALERT` | A signal to another task is the native stop call's authority (the caller's ancestry); a signal to itself reaches nothing. |
| 130 | `tkill` | needed | `SYS_ALERT` |  |
| 131 | `tgkill` | needed | `SYS_ALERT` |  |
| 132 | `sigaltstack` | deferred | none | Only `SS_DISABLE` is answered: no alternate stack. |
| 133 | `rt_sigsuspend` | needed | `SYS_SLEEP_UNTIL` | Waits as `nanosleep` does, until a signal is delivered. |
| 134 | `rt_sigaction` | needed | none |  |
| 135 | `rt_sigprocmask` | needed | none |  |
| 136 | `rt_sigpending` | needed | none |  |
| 139 | `rt_sigreturn` | needed | none |  |
| 160 | `uname` | needed | none |  |
| 166 | `umask` | needed | none |  |
| 167 | `prctl` | deferred | `SYS_INVOKE` | `PR_SET_NAME`/`PR_GET_NAME` and the child-subreaper pair (`DOMAIN_SUBREAPER`); every other option `-EINVAL`. |
| 172 | `getpid` | needed | none |  |
| 173 | `getppid` | needed | none |  |
| 174 | `getuid` | needed | none |  |
| 175 | `geteuid` | needed | none |  |
| 176 | `getgid` | needed | none |  |
| 177 | `getegid` | needed | none |  |
| 178 | `gettid` | needed | none |  |
| 214 | `brk` | needed | `SYS_INVOKE` | Personality-only: no native entry point moves the break; the native handler is reached through `SYS_INVOKE`. |
| 215 | `munmap` | needed | `SYS_MO_UNMAP` |  |
| 220 | `clone` | deferred | `SYS_FOREIGN_FORK`, `SYS_CAP_CLOSE`, `SYS_THREAD_CREATE` | Fork shape: a copy-on-write child reseeded from its row, counted against the row's `instances`; or a thread sharing the process's space, capabilities and descriptors. |
| 221 | `execve` | deferred | `SYS_INVOKE`, `SYS_CAP_CLOSE`, `SYS_SPAWN_EX` | Into the caller's own row, or another Linux row the caller holds a launch grant for; the target row's scheduling applies. |
| 222 | `mmap` | deferred | `SYS_MO_MAP`, `SYS_INVOKE` | Anonymous private maps through the memory-object calls; a file map through `SYS_INVOKE`. Never executable, never `MAP_FIXED`. |
| 226 | `mprotect` | needed | `SYS_INVOKE` | The pages' read and write permissions, exactly, through `SYS_INVOKE`/`DOMAIN_MPROTECT`; never execute. |
| 260 | `wait4` | needed | `SYS_INVOKE` | Reaps a child of the process. |
