# The user shell

The interactive shell of AzOS is an ordinary ring-3 program. It holds almost
no authority of its own: **a command runs with the authority of the topology
row of the image that executes it**, never with the shell's. This note
describes how the shell is built, what the kernel provides to make it
possible, and what happens when it is not there.

Source: `userspace/services/sh/src/main.rs`, `crates/core/abi/src/ushell.rs`,
`crates/core/syscall/src/ushell.rs`.

## 1. What runs

A shell session is a handful of cooperating images. None of them is the
kernel, and each one's row is its whole authority.

| Image | Role | Authority (default topology) |
|---|---|---|
| `TERMD.ELF` | The terminal server. Owns console input, runs the line discipline (editing, echo, history, type-ahead) and serves the `Terminal` object. It is the *console program*. | Serves `endpoint.term`; claims console input; maps the kernel's input event ring (`input.events`, with a keyboard or mouse driver) and console screen (`console.screen`, with `FB_CONSOLE`); with the login service, the call right on `endpoint.login`. |
| `NAMESD.ELF` | The name server. Lends the shell an attenuated capability on `endpoint.term`. | Serves `endpoint.names`; may lend `endpoint.term`. |
| `SH.ELF` | The shell: parses a line, starts programs, owns the job table, builtins and environment. | The right to start a fixed list of images, the `/fat` and `/tmp` trees, a read-only root directory. No hardware. |
| `TOOLBOX.ELF` | One multicall image for the file, text and device tools. | Read-only root directory, the task view, the introspection regions (Kconfig `INSPECT`), `READ` on `net` and `clock`, the audio server's endpoint or `sound.0`, the call rights on the input server and the compositor where their rows exist, and `imports = ["vmctl"]` where the monitor's row exists. |
| `POWER.ELF`, `FLIGHT.ELF`, `BEHAVIOR.ELF`, `CONFIG.ELF`, `OTA.ELF` | One image per privileged family. | Their own family endpoint with read and write rights (`POWER.ELF` also reads one sensor endpoint and calls the `DevicePower` endpoints of the devices it manages). |
| `LOGIND.ELF` (Kconfig `CONSOLE_LOGIN`) | The login service (section 13). | Serves `endpoint.login`; the `login` op of `keys`; the right to start `SH.ELF`; the `inspect.logins` view. |
| `TRACECTL.ELF`, `WHY.ELF`, optional `PKG.ELF` and `BUSYBOX.ELF` | Tracer reader, decision query, package tool, BusyBox. | Their own rows. |

Beside the session sits the **recovery console**: a small kernel task that
takes the UART only when no user shell can (section 9).

The shell does not read the console. It is a client of the `Terminal`
interface: it asks the terminal server for a line, or for typed events while a
job runs. The kernel hands the owner of console input raw bytes and never
echoes, edits or interprets them.

Source: `crates/core/topology/src/builder.rs` (`SH_CAPS`, `TERMD_CAPS`,
`NAMESD_CAPS`, `POWER_CAPS`, `FAMILY_PERMS`, `TASK_SH_IMAGE`,
`TASK_TERMD_IMAGE`), `userspace/services/termd/src/main.rs`,
`userspace/lib/term/src/lib.rs`.

## 2. Principles

1. **The shell holds no hardware authority.** A command's capabilities are
   those its own row names. The shell cannot lend what it does not hold, so it
   cannot be a confused deputy for a tool.
2. **The kernel stays raw.** It provides bytes, a way to start a program, a
   wait, a byte ring in shared memory and a stop request. Line editing,
   history, quoting, redirection and job tracking are user code.
3. **Authority follows the bytes.** `SYS_SPAWN_EX` binds a program to its
   seccomp profile and its row by the SHA-256 of the file, not by the path that
   was typed. A renamed or copied binary gains nothing.
4. **No inherited authority.** A child gets its row's capabilities, the
   handles in the caller's move list, an argument and environment block and a
   working directory. Not the parent's filter, its capabilities or its
   descriptors.
5. **One mechanism per need.** For a native program, duplicating descriptors,
   the working directory, the environment and terminal size are user-space
   state; the kernel has no `dup`, no per-task path and no process groups. (A
   child under the in-kernel Linux personality has its descriptors and working
   directory kept by that personality instead.)

Source: `crates/core/syscall/src/ushell.rs` (`sys_spawn_ex`),
`crates/core/libsys/src/pure.rs` (`FdTable`), `userspace/services/sh/src/main.rs`.

## 3. Starting a program: `SYS_SPAWN_EX`

`SYS_SPAWN_EX` (syscall number 5) takes a path and an optional request block.
With no block it starts the image with its row's capabilities, class, priority
and memory budget. A caller needs three things: its seccomp profile lists the
call, the file's digest resolves to an image profile, and the caller holds a
launch grant (section 4) for that image. The image also needs a topology row;
without one the call is refused with `-EACCES`.

### 3.1 The request block

`SpawnReq` is a little-endian `repr(C)` structure of 184 bytes (version 1).

| Field | Meaning | Limit |
|---|---|---|
| `flags` | `SPAWN_F_DIE_WITH_PARENT` (1), `SPAWN_F_CONSOLE_IN` (4), `SPAWN_F_USER` (8) | other bits, including 2, are `-EINVAL` |
| `argv_ptr`, `argv_bytes`, `argc` | NUL-separated arguments | 1024 bytes, 16 strings |
| `env_ptr`, `env_bytes`, `envc` | NUL-separated `KEY=VALUE` strings | 1024 bytes, 16 strings |
| `cwd_ptr` | NUL-terminated working directory, or 0 | 64 bytes |
| `nmoves`, `moves[8]` | The move list | 8 entries, child fds 0 to 7, each named once |

`check_shape` validates everything that needs no user memory or capability
table. The kernel copies the block and what it points at before it looks at a
handle.

### 3.2 The move list

The move list is what replaces `dup2` for a child. An entry names a
`child_fd`, a `handle` the caller holds and the `perms` the child gets (0 keeps
the caller's). Three kinds of handle are accepted:

- A **file descriptor** (`Cap<File>`, not a directory tree). It is **moved**:
  the caller needs `TRANSFER` on it, the caller's handle goes stale, and the
  descriptor's owner is re-stamped to the child so the child's first read is
  not refused.
- A **pipe region** (`Cap<Shm>`, section 5). It is **shared**: the child gets a
  derived copy, the caller keeps its handle and mapping, and the caller needs
  `DUP` and `TRANSFER`.
- `MOVE_CONSOLE` (`0xFFFF_FFFF`) as the handle. It moves nothing; the child's
  fd is the console.

Anything else is `-ECAPKIND`. Rights may be kept or lowered, never raised
(`-ECAPPERMS`). One handle named by two fds (`> f 2>&1`) is moved once. A stale
handle is `-ECAPSTALE`. All entries are validated before the first one moves.
If a later step fails, what already moved is returned to the caller and the
child is not released.

### 3.3 The startup block

Before the child runs, the kernel writes a `StartupBlock` and the argument,
environment and directory strings at the top of its user stack, and passes the
block's address in the **second argument register** (`a1` on riscv64, `x1` on
aarch64, `rsi` on x86_64); the first register is zeroed by the spawn hand-off. The block is 120
bytes, begins with the magic `"KSB1"` and describes each of the eight child
fds as closed, the console, or a handle in the child's own table.
`azos_libsys::startup_init` validates it and builds the process state behind
`argv`, `getenv`, `cwd` and the descriptors. A program that never reads the
register is unaffected.

### 3.4 Descriptors in user space

`libsys` keeps a table of eight small descriptors over capability handles. `dup`
and `dup2` alias one handle in that table with no trap, and only the last
close of a handle reaches the kernel (`SYS_CAP_CLOSE`). Without a startup block
fds 1 and 2 are the console and the rest are closed. The kernel never sees an
alias.

### 3.5 Flags

- `SPAWN_F_DIE_WITH_PARENT`: when the spawner exits, the kernel force-stops the
  child (signal 1) by the path `SYS_ALERT` takes. The shell sets it on every
  job, so a shell that dies leaves no orphan writing under the next prompt.
- `SPAWN_F_CONSOLE_IN`: for a Linux-personality child only. The console's input
  owner (or a client of the owner, over a call capability on an endpoint the
  owner serves) lends console input to the child for the child's life; the
  owner reads none of it meanwhile, and `^C` becomes `SIGINT` for the child. A
  native child has no console read and the flag changes nothing for it.

- `SPAWN_F_USER`: the child is the session of the user the caller just logged
  in (console login, section 13). The caller must hold the one-shot login grant
  that the `keys` interface's `login` op armed for its Domain when it admitted a
  credential; the spawn spends it, and the child's Domain (and every Domain
  beneath it) is owned by the user's root (`owner_root`). Without a live grant
  the spawn is refused with `-EACCES` and nothing starts.

Source: `crates/core/abi/src/ushell.rs` (`SpawnReq`, `Move`, `StartupBlock`,
`layout_startup`, `MOVE_CONSOLE`, `SPAWN_F_*`), `crates/core/abi/src/syscall_nr.rs`
(`SYS_SPAWN_EX`), `crates/core/syscall/src/ushell.rs`
(`sys_spawn_ex`, `console_lender`), `crates/core/libsys/src/lib.rs`
(`startup_init`, `dup`, `dup2`, `getenv`, `cwd`), `crates/core/libsys-macros/src/lib.rs`,
`crates/core/sched/src/scheduler/lifecycle.rs` (`set_die_with_parent`,
`stop_die_with_parent_children`).

## 4. Launch grants

A launch grant is a `Cap<Launch>` (`ty::LAUNCH`, a class of the `Node` kind):
the right, with `EXEC`, to start one image. It is seeded from a `node` row
whose target is an image name and whose permission is `x` (`EXEC`):

```toml
caps = [ { kind = "node", target = "TOOLBOX.ELF", perm = "x" } ]
```

`SYS_SPAWN_EX` resolves the file's digest to an image name, interns the name
and checks the caller holds `EXEC` on it. The check is against what the bytes
are, not what the path says. A refusal is `-EACCES`, is recorded like other
typed capability denials and is logged as a refused spawn with a distinct
action code.

The grant is the lockdown mechanism (section 9). The default row of the shell
lists the tool images; a production topology can omit the privileged ones, so
typing `/fat/POWER.ELF` is refused at the call, not merely absent from the
search path.

Source: `crates/core/ipc/src/launch_cap.rs` (`launch_resource`,
`launch_resource_of`), `crates/core/abi/src/cap.rs` (`ty::LAUNCH`),
`crates/core/syscall/src/ushell.rs` (`SPAWN_REFUSED_ACTION_NO_LAUNCH`),
`crates/core/topology/src/parser.rs` (the `node` row), `crates/core/topology/src/builder.rs`.

## 5. Pipes

A pipe is **a byte ring inside a `Cap<Shm>` region**, not a kernel object. The
ring is a single-producer single-consumer stream with a header of end counts
and sleep events, and the futex is the doorbell. Reading and writing is a
memory copy; the kernel is entered only to create and map the region, to sleep
and wake, and to give an end up.

- The reader and writer **end counts belong to the kernel**. A creation holds
  both; a spawn move list counts the child's ends in the same step that shares
  the region; a process gives an end up with `MEMOBJ_END_DROP`; a process that
  dies has whatever it still holds given up. Programs only read the counts, so
  a program killed at any instruction cannot leave a count behind.
- In a move list the **read end goes to child fd 0 and the write end to any
  other fd**. A received region carries no role; its position says which end it
  is.
- End of file is "no writer left and the ring is empty". A write with no reader
  left reports the broken pipe: a native program sees `-EPIPE`, and the Linux
  runtime raises `SIGPIPE` itself.
- A write of at most `PIPE_BUF` bytes goes in whole or not at all; a larger
  write may interleave with other writers.
- The writers take a lock word around the head and the readers one around the
  tail, so several holders of one end are safe. The lock word records the
  owner's process id so the kernel can open a lock a dying holder owned.
- A process holds at most eight pipe regions (`MAX_PIPES`). A pipe end in a
  program is a *token*, a `u32` whose kind field is zero so it can never be
  mistaken for a capability; `file_read_typed`, `file_write_typed` and
  `close_typed` answer for a token, so a program that reads a descriptor needs no
  pipe-specific code.

A pipeline of up to four stages makes one region between each pair, shares the
write end with the producer at one of its fds and the read end with the
consumer at fd 0, and closes its own ends once the stages are running, so a
writer end kept by the shell cannot hold the next stage's input open.

Source: `crates/core/bytepipe/src/lib.rs`, `crates/core/libsys/src/pipe.rs`
(`MAX_PIPES`), `crates/core/abi/src/invoke.rs` (`MEMOBJ_END_DROP`,
`SHM_END_READ`, `SHM_END_WRITE`), `crates/core/ipc/src/memobj.rs`,
`userspace/services/sh/src/main.rs` (`run_pipeline`).

## 6. The console and the terminal server

**One reader at a time.** The UART fills one receive ring, and two readers of
one ring steal bytes from each other, so input has exactly one owner. The first
console wait with a non-empty buffer claims it; a second claimant gets `-EBUSY`;
the owner's exit releases it. The recovery console claims the same owner slot
as a kernel marker before its first read. The terminal server claims input at
start with a zero-timeout wait, so bytes typed early are kept, not lost.

**The console wait** is an op of the console capability (`LOG_CONSOLE_WAIT`),
which every task is seeded with and which an image's profile includes or not.
Only `TERMD.ELF` lists it. It returns the bytes read, 0 on timeout, `-EINTR` on
a stop request or a child's exit notice, and `-EBUSY` when another task owns
input. It parks on the receive interrupt where one is wired and otherwise polls
every 20 ms inside the call, so ring 3 never polls.

**The `Terminal` object** is an IDL interface served over `endpoint.term`. The
shell is its one client. State is set by typed operations (size, raw or cooked
mode, echo, prompt, foreground job); input is a stream of typed events:

| Event | Meaning |
|---|---|
| `Line` | A completed line (up to 255 bytes; the first 48 inline, the rest by `line_chunk`). |
| `Bytes` | Raw bytes, in raw mode. |
| `Interrupt` | The interrupt key, tagged with the foreground job it was addressed to. |
| `Eof` | `^D` on an empty line. |
| `Timeout` | Nothing arrived within the timeout. |

The line discipline lives in the server: printable insert, backspace and
Delete (`^D` on a non-empty line), `^A`/`^E` and Home/End, left and right (and
`^B`/`^F`), `^U`, `^W`, `^K` (kill to the end), up and down (and `^P`/`^N`)
through a 32-line history, `^L` redraw. A focus rule keeps a running job's typing out of
the shell: while a job holds the focus the server delivers only interrupts and
holds other bytes (256 of them) as type-ahead for the next line. The key `^C`
is an event in both modes; **nothing is signalled**, the client decides what an
interrupt means. A client's output does not pass through the server. Console
output has many writers (the kernel, the tools the shell starts and the shell),
so each writes the console directly with the console's write op, at most 4096
bytes per call.

**Getting the capability.** The shell's row holds no grant on `endpoint.term`.
It lists the name in `imports`, the kernel gives the row the call right on
`endpoint.names` stamped with the row's identity, and the name server lends a
derived call-only capability when asked. A name is never authority: the row
lists what it may ask for. The lend is a lease with a deadline; the shell's
transport asks again when a call is refused for a lapsed capability.

**Terminal size** comes from the server (`size`, default 80 by 24) and the shell
exports it as `COLUMNS` and `LINES`. There is no terminal-size syscall.

**Keys and the mouse.** Keys with no console byte (arrows, Home/End, Page
Up/Down, Insert/Delete, F1-F12, with their modifiers) and mouse events arrive
from the PS/2 and virtio-input drivers on the kernel's input event ring, which
the server maps (`MemObj input.events`). It turns keys into the xterm CSI/SS3
sequences the editor and a raw-mode client read. With a framebuffer console it
also maps the screen region (`MemObj console.screen`) and, as gpm does on a
Linux console, gives the mouse a pointer cell, selection (drag, double click
for a word, triple click for a row), paste with the middle button and
scrollback with the wheel; a program that asked for mouse reporting
(`ESC [ ? 1000 h`, `1002 h`, `1003 h`) gets X10 or SGR reports instead. The
console wait serves both the typed bytes and the ring; no timer polls it.

The Linux personality's terminal (`/dev/ptmx`, termios) is not mapped onto this
object. A foreground Linux job reads the console through the kernel's own
discipline while the owner lends it input (section 3.5).

Source: `crates/drivers/sys/src/console_rx.rs` (`RxOwner`),
`crates/core/syscall/src/ushell.rs` (`sys_console_wait`),
`crates/core/abi/src/invoke.rs` (`LOG_CONSOLE_WRITE`, `LOG_CONSOLE_WAIT`),
`userspace/lib/term/src/lib.rs`, `userspace/services/termd/src/disc.rs`,
`userspace/services/termd/src/edit.rs`, `userspace/services/termd/src/{input,keys,mouse}.rs`,
`userspace/lib/names/src/lib.rs`,
`userspace/services/namesd`, `crates/core/topology/src/builder.rs` (`SH_IMPORTS`).

## 7. Stopping a job: `SYS_ALERT`

`SYS_ALERT` (syscall number 9) takes a task id, a *how* (`KILL_REQUEST` or
`KILL_FORCE`), a signal number from 1 to 31 and a flags word (`KILL_SUBTREE`).

- **Authority is a relation, not a name.** The caller must be an *ancestor* of
  the target, found by walking the parent chain at most `KILL_MAX_ANCESTRY` (8)
  steps. Anything else, a task that does not exist included, answers `-ESRCH`,
  so a task cannot probe task ids. Killing oneself is `-EINVAL`. A task the
  shell did not start is therefore out of its reach.
- **A request** sets a stop flag in the task and wakes any interruptible wait,
  which returns `-EINTR`. A program that blocks in a read, wait or sleep sees it
  with no setup; one that computes without ever blocking does not, and relies on
  force after a grace period.
- **Force** marks the task to terminate and also wakes every wait it has. The
  end happens at the target's next return to user mode, or at that wake, by the
  same path a user-mode fault takes, with exit code `128 + signo`. It is never
  applied inside a syscall: console output holds a line lock, and a task ended
  while holding it would leave the console wedged.
- `KILL_SUBTREE` applies to the target and its descendants (a bounded walk).
  The call returns how many tasks were signalled.

The shell uses it for `^C`: it asks, remembers the time, forces after a grace of
300 ms or a second `^C`, and reports 130. Together with
`SPAWN_F_DIE_WITH_PARENT` this means a crashed shell leaves no runaway job.

The shell is also a child **subreaper** (`DOMAIN_SUBREAPER`), so what a job
leaves running is adopted by the shell and reaped there.

`DOMAIN_WAIT` does not block: it reaps a finished child or answers `-1` when
none has finished. A blocked call to the terminal server does not wake when a
child exits either, so the shell asks the server for events with a timeout that
starts at 1 ms and doubles to 32 ms while a foreground job runs, and looks at its
jobs between calls.

Source: `crates/core/abi/src/syscall_nr.rs` (`SYS_ALERT`),
`crates/core/abi/src/ushell.rs` (`KILL_*`), `crates/core/syscall/src/ushell.rs`
(`sys_task_kill`), `crates/core/abi/src/invoke.rs` (`DOMAIN_WAIT`,
`DOMAIN_SUBREAPER`), `userspace/services/sh/src/main.rs` (`wait_job_inline`,
`Job`).

## 8. Names, syntax and builtins

**Grammar.** One pipeline per line:

```text
line     := pipeline [ '&' ] [ '#' comment ]
pipeline := command { '|' command }
command  := { word | redirect }
redirect := '<' word | '>' word | '>>' word | '2>' word | '2>>' word | '2>&1'
```

Single quotes quote everything; inside double quotes `\"`, `\\` and `\$` escape
and `$NAME`, `${NAME}` and `$?` expand. An unset variable expands to nothing.
`;`, `&&`, `||`, `$(` and backquotes are refused, not guessed at. The limits are four
stages per pipeline, sixteen words per command and 1024 bytes of expanded words
per line.

**Resolution order.** A builtin (a name in the shell); then an *applet* (a name
compiled into the shell's table that runs inside `TOOLBOX.ELF`); then each
directory of `PATH` (default `/fat`) as `<DIR>/<NAME>.ELF`. A builtin that is
not also an applet cannot run in a pipeline or in the background; a name that
is both (`echo`, `cat`, `ls`) is a builtin as a single foreground command and
the applet in a pipeline.

**8.3 names.** The volume is FAT32 with 8.3 names, upper-cased: a command name
of more than eight characters before `.ELF` is refused with a message that
names the limit. Lookup is by file name; the child runs under the profile and
row of the file's *bytes*, so a copied binary does not gain authority. Inside
the multicall image an applet is chosen by `argv[0]`; the authority is the
image's row whatever `argv[0]` says.

**Builtins:** `help echo cd pwd exit export unset env jobs wait kill history
true false ls cat mkdir rm uptime type`.

**Applets of `TOOLBOX.ELF`:** `args beep cat echo false host input inspect log ls
ntp ps sleep spin true vm wc window yes`.

**Privileged tools**, each its own image and row: `power`, `flight`,
`behavior`, `config`, `ota`, plus `tracectl` and `why`. They run only if the
shell's row holds a launch grant for them, and each calls its family's typed
interface, where the kernel checks the *calling image's* capability on every
call.

**State kept by the shell:** the environment (at most 16 strings, 1024 bytes;
there is no global environment), the working directory (the kernel has none;
paths are made absolute in user space before any call), a table of eight jobs
and the status for `$?`. Redirections open beneath the root directory
capability the row grants (`NODE_OPENAT`; there is no open by absolute path),
and a change to the tree additionally needs a writable tree that covers the
file.

**Exit.** `exit` tells the terminal server the status and exits with it.
Status 0 ends the session cleanly and the console passes to the recovery
console; a non-zero status is a failed session, and the supervisor restarts it.

Source: `userspace/services/sh/src/parse.rs`, `userspace/services/sh/src/path.rs`
(`APPLETS`, `elf_name`), `userspace/services/sh/src/main.rs` (`BUILTINS`,
`open_redirect`, `quit`), `userspace/services/toolbox/src/main.rs`,
`userspace/services/famtools`, `userspace/services/power`,
`crates/core/abi/src/invoke.rs` (`NODE_OPENAT`).

## 9. Authority: rows and profiles

**The shell's row.** Class `session` (the interactive class: fair-share at the latency QoS tier, reported as `interactive`), priority 26, a 64-page frame budget
and no heap. It imports `term`. Outside lockdown it holds a launch grant for
each tool image, read and write on `/fat` and `/tmp`, the read-only root
directory the redirections open beneath, and the full task view (`"tasks"`).
It holds no `Power`, motor, GPIO, PWM, I2C, socket or disk authority. Tools run
at priority 27, so a CPU-bound tool does not out-rank the shell on its hart.

**A policy row binds the shell's jobs.** The row `shjobs` is a subtree policy
on the shell's domain: every program the shell starts, and the shell, may not
create an endpoint or a port, whatever its own row grants. A program typed at a
prompt joins services other rows start; it does not become one.

**The shell's seccomp profile** lists exactly the calls its source issues:
`SYS_EXIT`, `SYS_INVOKE`, `SYS_SLEEP_UNTIL`, `SYS_CAP_CLOSE`, `SYS_CAP_INFO`,
`SYS_SPAWN_EX`, `SYS_ALERT`, `SYS_IPC_CALL_V2`, `SYS_MO_CREATE`, `SYS_MO_MAP`,
`SYS_MO_UNMAP`, and the `SYS_INVOKE` ops for console write, the subreaper mark,
stat, open beneath a directory, `mkdir`, file read and write, wait, and
`MEMOBJ_END_DROP`. It has no fork, no hardware or network call, and no console
wait. `tests/host/seccomp-tests` derives each image's set from its sources and
requires the row to equal it. A call outside an image's row ends the task with
exit code 159 (a profile marked *audit* allows and records instead; only two
probe images are).

**Each image is its own sandbox.** `TERMD.ELF` is the only profile in
`IMAGE_PROFILES` that lists the console wait. `NAMESD.ELF` can look up handles
and serve; it has no spawn, kill, device, network or input call. `POWER.ELF` is
the only profile that lists the `power` interface, and each family tool lists
its own family's interface.

**Priority for the terminal side.** `TERMD.ELF` and `NAMESD.ELF` run at the
shell's priority, so the interrupt key is read as promptly as the shell can act
on it.

**Lockdown.** With `CONSOLE_LOCKDOWN` the built-in rows shrink. The shell may
start only `TOOLBOX.ELF`, may write `/tmp` and holds the read-only root
directory; it cannot change `/fat`, has no task view, and holds no launch grant
on the privileged tools, so they are refused at `SYS_SPAWN_EX` and recorded.
The kernel console task is not created at all (section 10). A privileged
service shell exists only if the *signed topology* gives an image's row those
capabilities; nothing on the console can grant them.

Source: `crates/core/topology/src/builder.rs` (`SH_CAPS`, `SH_CAPS_LOCKDOWN`,
`TOOLBOX_CAPS_LOCKDOWN`, `SH_PRIORITY`, `TOOL_PRIORITY`, `TASK_VIEW_CAP`, the
`shjobs` policy), `crates/core/sched/src/seccomp.rs` (`IMAGE_PROFILES`),
`crates/core/syscall/src/handlers.rs` (`SECCOMP_KILL_EXIT_CODE`),
`config/axes/Kconfig.security` (`CONSOLE_LOCKDOWN`).

## 10. Boot handoff and the recovery console

**Choosing the console program.** The Kconfig choice `CONSOLE_PROGRAM` names
what the kernel starts on the console: the native shell session (the default
on the edge and fleet profiles), BusyBox `sh` under the Linux personality, any
included image, a custom image, or none. With secure boot off and
`KERNEL_CMDLINE_INIT` (default `y`), `init=/fat/NAME.ELF` on the kernel command
line replaces it for one boot, provided the image has a row that says
`start = true`; with secure boot on (`SECURE_BOOT_ENFORCED`) or
`KERNEL_CMDLINE_INIT=n`, `init=` is ignored and the boot log says so.

**Order.** The launcher starts every other `start = true` row first, then the
console program, then the shell as the session's follower. The shell is started
after the terminal server so that its first call finds a server that already
holds the endpoint and console input. With the component manager enabled, that
manager starts the rows from the same plan.

**Console modes.** One kernel module keeps four states: `Pending` (no user
program has taken input yet), `UserUp`, `Restarting` (the owner of input died
and the supervisor is restarting it) and `Recovery`. The mode follows the
*owner of console input*, which in the native session is the terminal server:
its exit releases input, and the kernel learns from the supervisor whether a
successor is coming.

The recovery console takes the console at boot, without waiting, when:

- the build has no console program,
- the machine is in safe mode,
- the topology does not start the console program, or
- the volume does not carry its image.

It takes the console later when:

- no user program has taken input within `SH_START_TIMEOUT_S` (default 10)
  seconds of boot or of its last death, which covers a missing actuation gate or
  a respawn that keeps failing before it reads,
- the supervisor gave up on the console program, or
- the session ended with status 0: `exit` hangs the terminal up with the
  shell's status, the server exits with it, and the rows of both programs
  restart only on failure, so a clean `exit` does not respawn them.

While a user program owns input, the recovery console cannot read the UART.
There is no physical-console takeover from a wedged but live shell.

**What the recovery console keeps.** What a machine without a working ring 3
needs to be diagnosed and repaired: status (`help`, `mem`, `uptime`, `drvls`,
`security`, `estop`), file and diagnosis commands (`ls`, `cat`, `crash`, `why`),
repair (`ota`, `config`, `ifconfig`, `dhcp`), the live update of a supervised
server (`swap`), measurement (`wcet`, `bench`), and the two exits `reboot` and `shutdown`, which are checked
against the `power` endpoint's write right. Its prompt differs from the user
shell's, so the two are never confused.

**Configuration.** `RECOVERY_CONSOLE=n` creates no kernel console at all
(allowed in a release image, at the cost of a board that cannot be repaired from
the console if ring 3 fails). `CONSOLE_LOCKDOWN` forces it off, in safe mode
too. The per-command authority table that the recovery console and the typed
calls of the privileged tools share is `AUTHORITY_TABLE`.

Source: `kernel/src/console_mode.rs`, `kernel/src/boot/launch.rs`
(`boot_launch_task`, `for_each_launch_row`), `kernel/src/tasks/system.rs`
(`recovery_task`), `kernel/src/main.rs`, `crates/core/recovery/src/lib.rs`,
`crates/core/ipc/src/authority_policy.rs` (`AUTHORITY_TABLE`),
`tools/gen_userspace_kconfig.py` (`CONSOLE_PROGRAM`),
`config/subsys/Kconfig.console` (`USER_SHELL`, `SH_START_TIMEOUT_S`, `RECOVERY_CONSOLE`,
`KERNEL_CMDLINE_INIT`).

## 11. Failure behaviour

| Event | Result |
|---|---|
| The shell exits non-zero (`exit 1`) | The shell hangs the terminal server up with its status and the server ends with it, so both fail together. The component manager reaps both ends before it starts anything, then restarts the server and the shell behind it (the shell's `imports` make the server and the name server its dependencies: the manager's plan spells them `endpoint.term`, `endpoint.names`), each within its own restart burst; the server's named endpoint is kept for its successor, so the name server's right to lend `term` stays valid. The shell's jobs die with it (`SPAWN_F_DIE_WITH_PARENT`); descriptors and pipe ends are released by the normal exit path. |
| The shell faults | The manager restarts the shell within the burst; the terminal server stays up, and the new shell puts the terminal back into cooked mode with echo and the shell in focus. |
| The terminal server is gone | Console input is released. The manager restarts the server and stops and restarts the shell behind it (a forced stop spends none of the shell's burst). |
| The restart burst is exhausted | When the shell and the terminal server fail together, the manager gives up on the terminal server (the console program) and the shell is given up on or blocked behind it, whichever end it reaps first. The server's death released console input; nothing takes it within `SH_START_TIMEOUT_S`, and the recovery console takes over (not under lockdown). A shell that alone exhausts its burst while the server lives leaves the server holding console input: the manager does not tell the kernel, so the recovery console does not take over. |
| The shell image is replaced by one whose digest is unbound | `-EACCES`, recorded; the recovery console takes over. |
| A job blocked in a pipe read | A stop request wakes it with `-EINTR`; force also wakes it and ends it at the wake. |
| A job that never blocks | Only force stops it, after the grace. |
| The console receive ring overflows with no reader | Bytes are dropped. |

Source: `userspace/services/sh/src/main.rs` (`terminal_gone`, `quit`),
`userspace/services/compmgr/src/tree.rs`, `kernel/src/console_mode.rs`
(`user_shell_exited`, `manager_restarts`).

## 12. Limitations

- **No process groups, sessions or job stop.** There is no `^Z`, `fg` or `bg`;
  jobs run in the foreground or with `&`. A stop request reaches a program only
  as `-EINTR` on a wait; a computing loop is ended by force.
- **No stop word in the task page.** The spawn flag `SPAWN_F_MAP_TASK_PAGE` is
  reserved and refused with `-EINVAL`.
- **Kill reaches descendants only.** Stopping anything the shell did not start
  is not possible from the shell.
- **No `;`, `&&`, `||` or command substitution.**
- **8.3 command names.** A command name is at most eight characters.
- **One client per terminal server.** The Linux personality's pseudo-terminal is
  not mapped onto the `Terminal` object.
- **For native programs the kernel has no working directory, `dup` or
  environment**, by design; user space keeps them, so a program that does not
  use `libsys` sees none.
- **Privileged operations other than the five families** have no ring-3 form
  and remain in the recovery console.

Source: `crates/core/abi/src/ushell.rs` (`SPAWN_F_MAP_TASK_PAGE`),
`crates/core/syscall/src/ushell.rs` (`sys_task_kill`),
`userspace/services/sh/src/parse.rs`, `userspace/services/sh/src/path.rs`,
`userspace/lib/term/src/lib.rs`.

## 13. Console login

With Kconfig `CONSOLE_LOGIN`, the login service's image on the volume (`USERSPACE_LOGIND`) and a
user enrolled in the signed topology (a `[login.NAME]` row), `SH.ELF` is not started
by the component manager: `LOGIND.ELF` starts it as the session of a user after a
secure-attention login (`SPAWN_F_USER`, section 3.5). The chain, the credential and the grant
are in [security.md](../security.md#console-login). The shell sees `USER=<name>` in its
environment and the prompt `<name>@azos$ ` (the system's shell keeps `azos$ `). Exiting the
shell logs the user out and the terminal server returns to the locked console.

Source: `userspace/services/sh/src/ident.rs`, `userspace/services/logind/src/{main,daemon}.rs`,
`userspace/services/termd/src/{secure,service}.rs`.
