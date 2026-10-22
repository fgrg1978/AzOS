<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# Ring-3 services

The programs under `userspace/services/`: what each one is for, the interface it
serves or calls, and the authority its topology row gives it. For writing a new
program see [sdk.md](sdk.md); for the options that include or start a service see
[config.md](config.md); for the hypervisor monitor in depth see
[virtualization.md](virtualization.md).

## How a service gets its authority

Source: `crates/core/topology/src/builder.rs`, `crates/core/sched/src/seccomp.rs`,
`tools/gen_userspace_kconfig.py`.

- **A row, named after the image.** The kernel seeds a spawned image's capabilities from
  the topology row named after it (an upper-case 8.3 name such as `NAMESD.ELF`).
  The built-in topology (`default_minimal` in `crates/core/topology/src/builder.rs`)
  holds the rows below; a signed `CAPS.TOML` writes its own. A row is the program's
  whole authority: spawning another program lends it nothing.
- **A system-call filter.** Each image has a profile bound to the SHA-256 of its image
  (`IMAGE_PROFILES` in `crates/core/sched/src/seccomp.rs`). Every system call a program
  makes is a `sys::name(..)` call, so `tests/host/seccomp-tests` derives the profile
  from the sources.
- **Endpoints, with split rights.** A service endpoint has a serving half and a calling
  half. `READ` on `endpoint.<name>` claims the endpoint for the server; `WRITE` is the
  right to call it and claims nothing. A grant with `transfer = true` lets the holder
  derive an attenuated copy for another task.
- **Names are not authority.** A task obtains the endpoint of a service through the
  name server (`namesd`): its row lists the names it may import, and the answer is a
  derived call-only capability or a recorded refusal.
- **Started by.** A row with `start = true` is started at boot by `compmgr`, which the
  kernel starts and restarts itself (the one ring-3 image the kernel supervises: a
  supervisor does not supervise itself). That includes the ring-3 host of a driver that
  moves between hosts at run time (`stateless`, today the buzzer): it stays up, and the
  kernel's placement controller only routes calls between that host and the kernel one.
  Which rows exist and which start depends on Kconfig (the third column below).
- **Image options.** A crate declares the images it builds in `[package.metadata.azos]` of
  its `Cargo.toml`; `tools/gen_userspace_kconfig.py` turns them into `make config`
  options.

Rights in the table: `R` read, `W` write, `X` exec, `RW`, and `+transfer` for a grant
that may be lent. `ROOT_RO` is a read-only directory capability on `/`, the root beneath
which a program opens its files; it names files and changes none.

## Summary

Source: `crates/core/topology/src/builder.rs` (the `*_CAPS` constants and the `push_task` calls of `default_minimal`).

| Image | Directory | Starts | Serves | Calls | Row capabilities |
|---|---|---|---|---|---|
| `COMPMGR.ELF` | `userspace/services/compmgr` | always, by the kernel | nothing | | R+M `MemObj inspect.components`, X on every row it starts |
| `NAMESD.ELF` | `userspace/services/namesd` | with the native shell session | `endpoint.names` (`Names`) | | R `endpoint.names`, W+transfer `endpoint.term`, R+M `MemObj inspect.names` |
| `TERMD.ELF` | `userspace/services/termd` | console program | `endpoint.term` (`Terminal`) | | R `endpoint.term`, RWM `MemObj input.events` (with a keyboard/mouse driver), RWM `MemObj console.screen` (with `FB_CONSOLE`) |
| `SH.ELF` | `userspace/services/sh` | with `TERMD.ELF` | nothing | `Terminal`, `Names` | X on the tool images, RW `/fat`, RW `/tmp`, `tasks` view, `ROOT_RO` |
| `TOOLBOX.ELF` | `userspace/services/toolbox` | by the shell | nothing | `sound.0` or `endpoint.audio` (`beep`), `endpoint.input` (`input`), `endpoint.compositor` (`window`) | `tasks` view, R `net`, R `clock`, RW `sound.0` (or W `endpoint.audio`, lent, with Kconfig `AUDIOD`), W `endpoint.input` (with Kconfig `INPUTD`), W `endpoint.compositor` (with Kconfig `COMPOSITOR`), inspect regions (Kconfig `INSPECT`), `ROOT_RO` |
| `POWER.ELF` | `userspace/services/power` | by the shell | nothing | `power` | RW `power`, R `sensor.9`, X `endpoint.pm-gpio` and `endpoint.pm-ina` (the drivers' `DevicePower`) |
| `TRACECTL.ELF` | `userspace/services/tracectl` | by the shell | nothing | `trace` | RW `trace` log, RW `/fat`, `ROOT_RO` |
| `FLIGHT.ELF`, `BEHAVIOR.ELF`, `CONFIG.ELF`, `OTA.ELF` | `userspace/services/famtools` | by the shell | nothing | `flight`, `behavior`, `config`, `ota` | see [famtools](#famtools) |
| `DECISD.ELF` | `userspace/services/decisd` | with Kconfig `DECISION_REFUSALS_DURABLE` or `DECISION_RECORDS_DEV` | `endpoint.decisions` (`Decisions`) | | R `endpoint.decisions`, `tasks` view, R+M `MemObj inspect.public`, R+M `MemObj inspect.admin` |
| `LOGD.ELF` | `userspace/services/logd` | with Kconfig `KLOG` | nothing | | R+M `MemObj klog.ring`, RW `/fat`, `ROOT_RO` |
| `INPUTD.ELF` | `userspace/services/inputd` | with Kconfig `INPUTD` | `endpoint.input` (`Input`) | | RW+transfer `endpoint.input` (R serves it; W+transfer is the source of its warrants), RWM `MemObj input.events` |
| `COMPSRV.ELF` | `userspace/services/compositor` | with Kconfig `COMPOSITOR` | `endpoint.compositor` (`Compositor`) | `display.0`, `endpoint.input` (trusted), `endpoint.decisions` | R+W+transfer `endpoint.compositor` (R serves it; W+transfer is the source of its windows' rights), RWX `display.0`, WX `endpoint.input` (the kernel badges it as the trusted surface's), W `endpoint.decisions` (where `DECISD.ELF` runs) |
| `WHY.ELF` | `userspace/services/why` | by the shell | nothing | `endpoint.decisions`, `endpoint.rpc-decisions` | W both, R `entropy`, `ROOT_RO` |
| `PKGD.ELF` | `userspace/services/pkgd` | every hardware class but embedded | `endpoint.packages` (`Packages`) | `ota`, a pinned HTTPS source (a TCP socket, by its seccomp profile) | R `endpoint.packages`, RW `/fat/PKG`, R `ota`, R `entropy`, `ROOT_RO` |
| `PKG.ELF` | `userspace/services/pkg` | by the shell | nothing | `endpoint.packages` | W `endpoint.packages`, `ROOT_RO` |
| `RPCSRV.ELF` | `userspace/services/rpcsrv` | with Kconfig `RPC_PEER_NODE` set | `endpoint.rpc-*` proxies | the real endpoints it exports | R `endpoint.rpc-decisions`, W+transfer `endpoint.decisions`, R `entropy`, R `linkkey` (`node_key` only), R+M `MemObj inspect.rpc` |
| `RPCQUIC.ELF` | `userspace/services/rpcquic` | with Kconfig `RPC_QUIC` | nothing | UDP to `rpcsrv`, QUIC to the peer | R `entropy` |
| `ZENOHD.ELF` | `userspace/services/zenohd` | Kconfig `ZENOH_GW` | Zenoh queryables | `endpoint.decisions` | W+transfer `endpoint.decisions`, R `entropy` |
| `MCPD.ELF` | `userspace/services/mcpd` | Kconfig `MCP_BRIDGE` | MCP tools | `endpoint.decisions` and the endpoints it fronts | W+transfer `endpoint.decisions`, R `entropy`, R `linkkey` (`node_key` only), R+M `MemObj inspect.mcp` |
| `PTPD.ELF` | `userspace/services/ptpd` | Kconfig `PTPD` | nothing | `clock` | W `clock`, R+M `MemObj inspect.clock` |
| `LOGIND.ELF` | `userspace/services/logind` | Kconfig `CONSOLE_LOGIN` (default n) | `Login` on `endpoint.login` | `TERMD.ELF` calls it | `READ` `endpoint.login`, `EXEC` `keys` masked to `login`, launch `SH.ELF`, R+M `MemObj inspect.logins` |
| `AUDIOD.ELF` | `userspace/services/audiod` | Kconfig `AUDIOD` | `endpoint.audio` (`Sound`) | `sound.0` | R `endpoint.audio`, RW `sound.0`, W `time` (the mixer thread's own deadline reservation, Kconfig `AUDIOD_PUMP_*`); the row itself is best effort |
| `VMMD.ELF` | `userspace/services/vmmd` | wherever the hypervisor core is built (Kconfig `HV`) | nothing | `Vm`, `Vcpu` | RX `vm.0`, RWX `vcpu.0.k`, RW `/fat/VM`, `ROOT_RO` |
| `LXSRV.ELF` | `userspace/services/lxsrv` | `lx-server` builds | nothing | | R `entropy`, `ROOT_RO` |
| `MLSRV.ELF` | `userspace/services/infsrv` | by the kernel's behavior task | `Infer`, `Decisions` (its receipts) and the verdict-log lease on `endpoint.infer` | | READ `endpoint.infer`, `WRITE` `memctl`, `ROOT_RO` |
| lxrt | `userspace/services/lxrt` | mapped into each Linux process | the Linux system-call surface | | no row |
| `BRAINCLI.ELF`, `REFLEX.ELF` | `userspace/services/brain_client`, `userspace/services/reflex` | the `autorun` choice | | | `BRAINCLI.ELF` `ROOT_RO` only; `REFLEX.ELF` none; the grant a running one gets is the `autorun` row's |

The interfaces the services share, from `userspace/lib/`:

| Interface | Id | Crate | Ops |
|---|---|---|---|
| `Names` | `0x4E41_4D45` | `userspace/lib/names` | `lookup`, `who_serves` |
| `Terminal` | `0x5445_524D` | `userspace/lib/term` | `size`, `set_size`, `set_mode`, `set_echo`, `set_foreground`, `set_prompt`, `begin_line`, `redraw`, `read_event`, `line_chunk`, `history`, `hangup` |
| `Decisions` | `0x4445_4349` | `userspace/lib/decisions` | `query`, `get` |
| `Login` | `0x4C4F_474E` | `userspace/lib/login` | `state`, `login`, `end` |
| `Packages` | `0x504B_4753` | `userspace/lib/packages` | `admit`, `install`, `remove`, `installed`, `update`, `fetch`, `fetch_update` |
| `Input` | `0x494E_5054` | `crates/core/devif/src/input.rs` | `take_focus`, `release`, `trusted`, `status` |
| `Compositor` | `0x434D_5053` | `userspace/lib/compositor` | `attach`, `detach`, `status` |

## compmgr

Source: `userspace/services/compmgr/src/main.rs`, `userspace/services/compmgr/src/tree.rs`,
`userspace/services/compmgr/src/contracts.rs`.

The component manager is the one row the kernel starts (and restarts, on failure) on every
build. It reads the signed topology's startable rows from its view region
(`MemObj inspect.components`, granted only to its row; a row whose image is not on the
volume is listed with `start` 0, a row that moves between hosts is not listed), starts each with `SYS_SPAWN_EX` in dependency order, supervises them, and
writes one console line for every start, restart, clean end, give-up and refusal. Its row
holds `EXEC` on each image it starts, because `SYS_SPAWN_EX` checks a launch grant on the
image whoever the caller is (for a row an applied package brought, the boot adds that grant
to the manager's row once the package is admitted, and records it as a decision); a child holds what its own row grants: the manager lends it
no handle, environment or descriptor, and a child dies with the manager. The kernel gives
the console program the console when the manager starts it (arguments, descriptors 0-2,
console input for a Linux program), so the manager knows nothing of it.

There is no `depends_on` key in the topology: a dependency is a consequence of authority.
A component depends on every listed component that serves an endpoint it needs, and the
start order is the view's order moved only as far as the dependencies require. Components
on a cycle are reported as blocked and not started. The restart strategy follows the IDL
failure contract of the interface a component serves (the strongest `#[on_failure(..)]`
among its ops, `contracts.rs`), with a restart intensity limit. The decisions are the
pure `tree.rs`; `main.rs` is the loop around them.

## namesd and termd

Source: `userspace/services/namesd/src/main.rs`, `userspace/services/namesd/src/service.rs`,
`userspace/lib/names/src/lib.rs`, `userspace/services/termd/src/main.rs`,
`userspace/services/termd/src/disc.rs`, `userspace/services/termd/src/edit.rs`,
`userspace/lib/term/src/lib.rs`.

`namesd` is the name server. Its row is the whole name space: it serves `endpoint.names`
and holds the lendable calling capability on the endpoints it may lend (today
`endpoint.term`). `Names::lookup` returns, for a name the caller's row imports, a derived
capability with the call right only (not `DUP`, so the borrower cannot pass it on),
expiring after `NAMES_LEND_TTL_MS` (a lapsed handle is refused and the borrower asks
again). For any other name nothing is lent and the server records the refusal.
`Names::who_serves` returns the name of the task serving an endpoint, or zero. The caller
is identified by the badge the kernel stamped from its row. It reads the rows' imports and
the pool index of each endpoint it holds from its view region (`MemObj inspect.names`).

`termd` is the terminal server and the console program of the native shell session. It
owns the console's input (claimed with `LOG_CONSOLE_WAIT`), runs the line discipline
(cooked editing, echo, history, Ctrl-C as a typed event) and serves the `Terminal` object
to one client, the shell, on `endpoint.term`. Both servers are request-driven: accept,
dispatch, reply.

`termd` is also the console's input consumer, as gpm is on a Linux console
(`keys.rs`, `mouse.rs`, `input.rs`). The kernel's input drivers (PS/2 on x86_64,
virtio-input on all three ISAs) publish every event the console has no byte for into one
ring, in one word format (`crates/drivers/input/wire`): arrows, F-keys, Home/End,
PgUp/PgDn, Ins/Del, the modifier keys, mouse buttons, axes and wheel. The ring is a
kernel-owned memory object that the row grants as `MemObj input.events` (`READ|WRITE|MAP`,
no `DUP`); `termd` maps it and drains it with loads and stores, no call per event. One
task cannot wait on the UART and on a ring at once, so the console wait is also the wait
for the ring: `termd` announces on the ring's consumer flag before it sleeps in
`LOG_CONSOLE_WAIT`, and the driver whose event finds the flag set nudges that wait
(`uart::rx_nudge`) and wakes the parked reader as it does for a byte; the wait returns 0
bytes early and `termd` drains the ring. No timer: an idle prompt sleeps until a byte, an
event or the caller's deadline. The producer also counts the events it drops on a full
ring in the region (`DROPS_OFFSET`); when the count moves and the ring is drained, `termd`
lets go of the modifiers and buttons it was tracking, since a dropped release would leave
them stuck. While the console's input is lent to a Linux job the wait is timer-only, so
events are acted on at the caller's next call.

* **Keys** become the xterm sequences the line editor and a raw client read: `ESC [ A`,
  `ESC [ 1 ; 5 C` with modifiers, `ESC [ 3 ~`, `ESC O P`.
* **The mouse** needs the screen. With `FB_CONSOLE` the framebuffer console publishes the
  text on the screen, `FB_CONSOLE_SCROLLBACK` lines of scrollback and the mouse modes
  programs set (`ESC [ ? 1000/1002/1003/1006 h|l`, seen in the console's output) into a
  second region, `MemObj console.screen`, and draws the overlay `termd` writes into it: a
  pointer cell and the selection in inverse video, and the view scrolled back. `termd`
  asks for a redraw by writing one NUL byte to the console (a byte the grid and a serial
  line take for nothing). Left drag selects (rows the terminal wrapped itself are
  joined, the others end in a newline), double click selects a word, triple click a row,
  the right button extends, the middle button pastes the copy into the terminal input,
  the wheel scrolls the scrollback, and a typed byte hides the pointer and returns to the
  live screen. When a program has set a reporting mode, buttons, motion and the wheel go
  to it as X10 or SGR reports instead (Shift gives the selection back).
* Without the grants, or without a framebuffer, `termd` serves as before: the keys still
  work, there is no screen to point at.

## sh and toolbox

Source: `userspace/services/sh/src/main.rs`, `userspace/services/sh/src/parse.rs`,
`userspace/services/toolbox/src/main.rs`.

`SH.ELF` is the user shell: pipelines, redirection and jobs. It reads no console input; it
asks `termd` for a line and for typed events. It runs each command as a child with
`SYS_SPAWN_EX` under the child's own system-call profile and topology row. The shell can
start only images its row holds an `X` (launch) grant for, and lends a child only the
descriptors and pipe ends it moves to it (a pipe is a byte ring in a shared region,
`azos_libsys::pipe`). Ctrl-C reaches it as a typed `Interrupt` event naming the foreground
job; the shell asks the job to stop (`SYS_ALERT`) and forces it after a delay or on a
second Ctrl-C. It has no heap. Under Kconfig `CONSOLE_LOCKDOWN` its row shrinks to launch
rights on `TOOLBOX.ELF`, `/tmp` read-write and `ROOT_RO`.

`TOOLBOX.ELF` is the multicall tool image, dispatched on `argv[0]`:

| Applet | What |
|---|---|
| `args` | prints argv, the environment and the working directory |
| `cat`, `echo`, `ls`, `wc`, `yes`, `sleep`, `true`, `false` | the usual |
| `spin` | computes forever without a system call |
| `ps` | the task list from the introspection tree |
| `inspect` | the kernel's introspection tree, a subtree such as `metrics`, or `-j` for a Perfetto counter trace |
| `log [-n N] [-l LEVEL] [-m MODULE]` | the kernel log `logd` keeps in `KLOGn.TXT`: the last N lines (20; 0 for all) at or below LEVEL (`e`, `w`, `i`, `d`) from modules starting with MODULE, oldest first |
| `host NAME` | the A and AAAA records of a name, from the stack's resolver (`Net::resolve`) |
| `ntp` | the SNTP client's server and last exchange (`Net::ntp_status`) and, from `Clock::status`, the clock discipline's state |

It reads and writes the descriptors the shell moved to it and opens files beneath
`ROOT_RO`. Its row grants the full task view (for `ps`), `READ` on the `net` and `clock`
endpoints (`host`, `ntp`) and, with Kconfig `INSPECT`, the `inspect.public` and
`inspect.admin` regions; a stop request ends its waits and it exits 130.

## power, tracectl and famtools

Source: `userspace/services/power/src/main.rs`, `userspace/services/power/src/policy.rs`,
`userspace/services/tracectl/src/main.rs`, `userspace/services/famtools/src/bin/flight.rs`,
`userspace/services/famtools/src/bin/behavior.rs`,
`userspace/services/famtools/src/bin/config.rs`, `userspace/services/famtools/src/bin/ota.rs`.

**power.** The power policy server and the shell's power tool. Policy is decided here and
the kernel enforces limits: the server applies a profile (a table per preset) through the
kernel's `Power` interface on the `power` endpoint, and the kernel answers each call with a
verdict, refusing what would break a floor (the deadline floor of an admitted
reservation, the WCET floor of the safety path, the last CPU of a domain) and recording the
refusal. It also keeps the devices' runtime power (the idle timeout of each ring-3 driver
that serves `DevicePower`) and reads the battery from `sensor.9`, turning it into a charge
that selects a degrade level from the topology's `[degrade.NAME]` rows. The preset comes
from the signed topology's `[energy] mode` (`performance`, `balanced`, `endurance`)
unless one is named.

| Command | What |
|---|---|
| `power serve [PRESET]` | apply the profile, stay resident, re-apply it when another client moved the policy |
| `power apply [PRESET]` | apply once |
| `power state` | policy state, battery and statistics |
| `power devices` | runtime power of each tracked device |
| `power suspend`, `reboot`, `shutdown`, `sched_hz [HZ]` | the recovery console's commands as a client of the same capability |

**tracectl.** The reader of the kernel tracer. It maps the per-CPU trace rings under the
`Cap<Trace>` its row grants, is their single consumer, sets the class mask, and streams
decoded events to the console or a file. Run one reader at a time.

| Command | What |
|---|---|
| `tracectl info` | geometry, classes, mask, per-CPU drops |
| `tracectl start [CLASSES]`, `tracectl stop` | start or stop recording |
| `tracectl stream [-n N] [-t MS] [-c CLASSES] [-p MS] [-m N] [-q] [-o FILE]` | record and stream decoded records |
| `tracectl profile [-t MS] [-p MS] [-k KERNEL_ELF] [-u USER_ELF] [-o FOLDED] [-j PERFETTO]` | the sampling profiler (Kconfig `PROFILER`): folded stacks and a Perfetto trace |

Classes: `sched`, `irq`, `syscall`, `ipc`, `fault`, `proc`, `lat`, `prof`. Without the
capability it still asks, with handle 0, so the refusal is the kernel's and is recorded.

<a id="famtools"></a>**famtools.** Four one-binary tools, each the ring-3 form of a recovery
console command through its family's typed call, under the capability its own row grants.
`FAMILY_PERMS` is `RW` unless the build sets `family-cap-canary`.

| Image | Usage | Row capability |
|---|---|---|
| `FLIGHT.ELF` | `flight arm`, `flight disarm` | none in the default topology; the `flight-tool-drivetrain` feature gives it the drivetrain motor capabilities and RW `flight` |
| `BEHAVIOR.ELF` | `behavior status`, `behavior enable LAYER`, `behavior disable LAYER` | `FAMILY_PERMS` on `behavior` |
| `CONFIG.ELF` | `config get KEY`, `config set KEY VALUE` | `FAMILY_PERMS` on `config` |
| `OTA.ELF` | `ota status`, `ota rollback`, `ota switch` | `FAMILY_PERMS` on `ota` |

`ota switch` makes the whole-system set that `pkg update` staged the one that boots next;
the kernel verifies it again and flips one boot record.

## inputd

Source: `userspace/services/inputd/src/main.rs`, `userspace/services/inputd/src/focus.rs`,
`crates/core/devif/src/input.rs`, `crates/drivers/input/src/events.rs`,
`userspace/services/toolbox/src/input.rs`.

The input server (Kconfig `INPUTD`, off unless set; the QEMU defconfigs set it): it delivers the keyboard and the pointer
to the one task that holds the focus. It serves the `Input` object on `endpoint.input`.
**`termd` keeps the console**: typed bytes still reach it through the console, it still
drains the first ring of the drivers' region (arrows, F-keys, the mouse on the framebuffer
console), and a build with no graphical client sees no change on the shell. With
`INPUTD` on, the drivers also write a second ring of the same region, the *stream*
(`STREAM_CAP` slots, `azos_input_wire::event`): every event the first ring gets and the key
events that became console bytes. `INPUTD.ELF` maps the region (`MemObj input.events`,
`READ|WRITE|MAP`, the object `termd` maps too: each reads and moves the tail of its own
ring) and reads the stream.

**Focus is a warrant.** `take_focus` derives a capability on the server's own endpoint with a
badge only the server names (`WARRANT_BADGE | generation`) and lends it with the call right
alone, together with a ring (`SpscRing`, one page) that is the holder's alone. The server
makes both before it takes anything from the old holder, so a grant that fails (`BUSY`)
leaves the focus where it was. A later grant, from anyone, revokes the old warrant
(`SYS_CAP_REVOKE`: the old holder's next call fails in the kernel), writes the close word
into the old ring and gives the region back; nothing is written to a closed ring. `release`
is accepted only through the live warrant. Events move through the ring with loads and
stores; the holder's wait is a timer (`input watch` looks every 20 ms) because the
drivers' wake protocol belongs to the terminal server's console wait. A holder that does not
read loses the newest events, counted in the ring. A new holder is told what is held down
(modifiers, mouse buttons) as presses at the start of its ring, and a dropped stream event
makes the server let go of everything it thinks is held and tell the holder with releases.

**The Secure Attention Key** is Ctrl+Alt+Delete (either Ctrl, either Alt). The Delete that
completes the chord, its repeats and its release are never delivered; the server counts the
chord on a page that tasks map read-only (`trusted`) and takes the focus from whoever has
it. Applications cannot fake the count, and a compositor that shows a trusted surface would
read it. **The chord also chooses who may hold the focus next.** `take_focus` needs only
the call right on `endpoint.input`, which every program started through `TOOLBOX.ELF` holds,
so on its own the chord would only revoke: a hostile former holder could ask again at once.
With a compositor in the build (Kconfig `COMPOSITOR`) the chord also sets *attention
pending*, and while it is set `take_focus` from any caller but the trusted surface is
refused (`DENIED`, recorded `NO_GRANT`, counted in `refused`; no ring is made and no warrant
derived). The trusted surface is the one caller whose call right carries `TRUSTED_BADGE`: the
compositor's row holds `endpoint.input` with `EXEC` beside `WRITE`, and the seeder
(`azos_ipc::cap_seed`) stamps that grant, as `power`'s calling grants are stamped. Its
`take_focus` clears the flag. Without a compositor row the gate is off (a gate with nobody to
open it would leave the focus unobtainable). The host suite pins both halves
(`tests/host/inputd-tests`, `tests/host/topology-tests`).

**Decision record.** Every focus move and refusal is a record (`from`, `to`, `reason`: the
shape of the kernel's `Rule::Focus`) and a console line. A ring-3 server cannot write the
kernel's journal; the warrant being minted and revoked is already there as `CapDerive` and
`CapRevoke` records of the server's task.

Two threads: the main thread accepts and dispatches (the row's `READ` grant stamps the endpoint
with the TID the program started as, and the kernel hands a call only to the thread with that
TID), the thread it creates reads the stream every `INPUTD_POLL_ACTIVE_MS` while a task holds the
focus and every `INPUTD_POLL_IDLE_MS` otherwise (the server must see the chord with nobody
focused), under one spin lock.

`input` (an applet of `TOOLBOX.ELF`, whose row holds the call right on `endpoint.input` with
`INPUTD`): `input watch [-n COUNT]` takes the focus and prints each event of its ring,
`input status` prints the server's counters, `input sak` the chord count.

## compositor

Source: `userspace/services/compositor/src/main.rs`, `windows.rs`, `trust.rs`, `bands.rs`,
`panel.rs`, `userspace/lib/compositor/src/lib.rs`, `userspace/lib/compose` (the pixel
engine), `userspace/services/toolbox/src/window.rs`.

The compositor (Kconfig `COMPOSITOR`, needs `INPUTD` and a framebuffer): the sole holder of
the kernel's `Display` interface and the trusted surface of the Secure Attention Key. Its row
is its whole authority (see the table). It serves the `Compositor` object on
`endpoint.compositor`.

**A window is a memory object the client made**: a control page (the damage ring) and the
pixels (XRGB8888), at most 64 pages in all (the object model's ceiling, so about 250x250
pixels). `attach` moves the object to the compositor with the window's shape and answers the
window's id and *a call right bound to that window*: derived from the compositor's own
endpoint with a badge only it names (`WINDOW_BADGE | id`), `WRITE` and not `DUP`. `detach`
is accepted only through that right: the plain call right every client holds (it attaches)
cannot take another client's window down. Drawing posts no call: the client pushes the
rectangle it changed into the ring in the control page and the compositor reads it on its
frame timer (`COMPOSITOR_FRAME_MS`); a full ring means the whole window changed. Tearing is
tolerated: a present may copy while the client draws.

**The surface.** The painter thread claims connector 0 (the kernel's text console stops
drawing; the UART still has its output), makes one full-screen surface and attaches it in
*bands*: physically contiguous memory objects of 64 pages, each holding whole rows (a 640x480
screen is 5, 1280x800 is 16, and a task may own half of `MAX_MEMOBJS`). Each frame it
composes the damage with `azos_compose` and calls `Display::present` with the damage
rectangles; every present is a console line (`[compsrv] present N: damage K rects`) for the
first sixteen and every 64th after. All Display calls come from this one thread, because the
claim belongs to the thread that made it. With no display the server still runs the trusted
path and `attach` answers `NOT_READY`.

**The trusted path.** The painter reads the chord count on the trusted page each frame. A
new chord puts the *trusted-path banner* on the screen at once, above every window (a window
that attaches later cannot cover it); `COMPOSITOR_BANNER_MS` later the compositor takes the
focus through its badged call right and gives it straight back, which opens the input
server's gate (see inputd) for the plain callers. In between no application can ask for the
keyboard, so none can put a look-alike prompt up and receive what is typed into it before the
user has seen the real banner. A second chord inside the interval extends it. Only the
compositor draws the banner and the panel below it, **"why was this refused"**: the newest
refusals and denials of the decision server (rule, verdict, subject, and the alternative the
rule rejected), fetched by a third thread, because a call on a server that does not answer
waits for ever and the banner and the hand-on must not wait for it.

`window` (an applet of `TOOLBOX.ELF`, whose row holds the call right on `endpoint.compositor`
with `COMPOSITOR`): `window show [-n FRAMES] [-s WxH] [-p X,Y]` makes a window, draws frames of
colour bars, posts their damage, holds the last and takes the window down through its own right;
`window status` prints the counters. The tool finds the compositor's endpoint among its call
rights by asking each one `status`; `input` does the same for the input server.

## logd

Source: `userspace/services/logd/src/main.rs`, `userspace/services/logd/src/store.rs`,
`crates/drivers/sys/src/klog.rs`, `crates/drivers/sys/src/klog/wire.rs`,
`kernel/src/boot/klog_region.rs`, `userspace/services/toolbox/src/log_view.rs`.

The sink of the structured kernel log (Kconfig `KLOG`; the ring and its protocol are in
[observability](observability.md#kernel-log)). Its row is its whole authority: `MemObj
klog.ring` (`READ|MAP`, so it can neither write the ring nor hand it on), the `/fat` tree
its files are written in, and the read-only root directory they are opened beneath. It
serves and calls no endpoint.

Every `LOGD_POLL_MS` it reads the records that arrived, drops those above
`LOGD_MAX_LEVEL`, and appends the rest as text lines (`seq ts_us cpu L module message`,
the message escaped so a record is one line) to the open file of a ring of
`KLOGn.TXT`: one append and one `fsync` per period, never one per line. A file that would
pass `LOGD_FILE_KB` is followed by the next of `LOGD_FILES_KEEP`, which is truncated, so
the log takes at most `LOGD_FILES_KEEP x LOGD_FILE_KB` of the volume. Each file opens
with a line `file N`, N one more than the file before it: the sequence numbers start
again at every boot, so the serial is what orders the files. After a restart it resumes
after the newest file's last record when the ring still holds that record byte for byte,
and from the ring's oldest record otherwise (a new boot). A write the volume refuses
leaves the cursor where it was, so the next period offers the same records again; a burst
that laps the ring between two polls is written as a `records lost: N` line. It runs at
the tools' priority: a real-time task never does block I/O.

`log` (an applet of `TOOLBOX.ELF`) reads the files back, ordered by serial, with no
capability beyond the root directory.

## decisd, why, pkgd and pkg

Source: `userspace/services/decisd/src/main.rs`, `userspace/services/decisd/src/bin.rs`,
`userspace/services/why/src/main.rs`, `userspace/services/why/src/cli.rs`,
`userspace/services/why/src/crash.rs`, `userspace/services/pkgd/src/main.rs`,
`userspace/services/pkgd/src/stage.rs`, `userspace/services/pkg/src/main.rs`.

**decisd** answers the `Decisions` object for whoever holds a call capability on
`endpoint.decisions`, from the binary records the kernel publishes in the admin
introspection region (`decisions/records/<n>`: the ring when Kconfig
`DECISION_RECORDS_DEV` is on, the journal of durable decisions with
`DECISION_REFUSALS_DURABLE`); its row holds the task view the admin region is granted
against. For each request it waits for the refresh that began after it and reads the
records again, so a request sees the decisions of the moment it is made. `query` returns the ids that pass
a filter, `get` returns one part of one record.

**why** is the client: a std program. It holds the call right
on `endpoint.decisions` and prints the chain a record holds: rule, verdict, subject, the
numbers the rule compared, the capability slot, the topology row, the image hash prefix and
the clock. `why --remote` asks the decision server of the peer node through the proxy
`endpoint.rpc-decisions`. `why crash [TID]` reads the minidump of a task a fault killed
from the dump files beneath `ROOT_RO`.

| Command | What |
|---|---|
| `why [--remote]` | the latest decisions, one line each |
| `why ID` | the chain behind decision `ID` |
| `why list [-r RULE] [-v VERDICT] [-s SUBJECT] [-a AFTER_ID]` | the decisions that pass the filter |
| `why crash [TID]` | the minidump of a task a fault killed |

Exit status: 0, 1 when the decision or dump is not held, 2 on a usage error or no endpoint,
3 when the server failed.

**pkgd** is the package installer and serves `Packages` on `endpoint.packages`:

| Op | What |
|---|---|
| `admit` | would the device take the package in the memory object? Changes nothing. |
| `install` | admit and stage the package and journal the decision; `#[once_only]`, `on_failure(degrade)` |
| `remove` | unstage a package by id; `#[once_only]` |
| `installed` | the id of the `index`-th staged package file |
| `update` | stage a signed whole-system update (kernel, userspace images, topology, configuration) into the inactive boot slot's directory under `/fat/PKG`, and read it back; nothing switches; `#[once_only]` |
| `fetch` | get the package from the source the rows in `/fat/PKG/SOURCE.CFG` describe (a pinned HTTPS server; in a development build also a TFTP server, below) and install it as `install` does; `#[once_only]`, `on_failure(degrade)` |

It verifies a package against the signers of the device's signed topology, admits its rows
as a topology delta (with the `neverallow` rules), stages the package, and journals the
decision on the native volume the topology mounts for it (`/pkg`, or `/fat/PKG` on the boot
volume when there is none), the two together durable or not at all. Whoever can write the
staging volume can stage a file without the installer, so the verdict is not a trust anchor:
a consumer verifies again. It holds no authority over the boot record; `ota switch` and the
kernel own the switch. `PKG.ELF` is its client (`pkg admit FILE`, `pkg install FILE`,
`pkg fetch`, `pkg list`, `pkg remove ID`): it reads the file into a memory object, hands the installer
that capability and the length, and prints the answer; `pkg fetch` hands it nothing, the
installer dials the source itself.

`pkgd` is a `std` program (the SDK, like `rpcquic`) because the fetch is TLS: `azos_tls`
(rustls with the rustls-rustcrypto provider, `third_party/vendor`) dials the address in
`SOURCE.CFG` and trusts only the SHA-256 pins listed there (no system CA store). The
connection decides nothing about the package: what arrives is verified, admitted and
staged exactly as a package a client handed over, and its own signature is what admits it.
A fetch that fails is a `step::FETCH` status (no source rows, rows, connect, TLS,
HTTP status, transfer) and records nothing. TLS needs the real-time clock to have been
set (NTP or PTP): until then there is no handshake. The row adds `READ` on `entropy`
(the handshake's keys) and the seccomp profile the TCP socket ops. The image is about 1 MiB;
the boot loader stages an autorun image in frames of exactly its size, refused with a
receipt past the budget of the row that bounds it, so no fixed buffer grows with it.

**Development source: TFTP.** With Kconfig `PKG_FETCH_TFTP` (it depends on
`BUILD_TYPE_DEV`; `pkgd` does not compile with it set in any other build) the same
`SOURCE.CFG` may instead hold two rows, `tftp=ADDR[:PORT]` (IPv4, port 69 by default)
and `file=NAME`, and `pkg fetch` reads the file from that TFTP server with the
`azos_tftp` client (`crates/net/tftp`) over a UDP socket of its own: on the development
host, `python3 tools/tftp_serve.py --dir DIR --port 6969`, or QEMU's
`-netdev user,tftp=DIR` (the server is 10.0.2.2). A package built and signed on the host
reaches the device without a disk cycle or a TLS server. TFTP authenticates nothing and
the installer asks it for nothing: it only delivers bytes, and the package is installed
because its own signature verifies against the device's signers, so a fetched package
has no more authority than one on the disk and a forged one is refused and journalled
(`tests/host/pkg-tests`, `tftp_source`; the gate rows `network: TFTP package install`
and `network: TFTP forged package canary`). A lost datagram is asked for again after a
second of silence (RFC 1350 §4) and a fetch is cut off after two minutes. The row and the
seccomp profile are unchanged: the UDP ops of the socket layer were already granted.

## rpcsrv and rpcquic

Source: `userspace/services/rpcsrv/src/main.rs`, `userspace/lib/rpc/src/lib.rs`,
`userspace/services/rpcquic/src/main.rs`, `userspace/lib/quic/src/lib.rs`.

`RPCSRV.ELF` is transparent RPC between nodes. It serves the proxy endpoints
(`endpoint.rpc-<service>`, the local face of a service on another node) and lends the
endpoints its `export` key offers to the topology's peer classes, one UDP datagram per
frame, with per-peer expiring warrants. When the endpoint behind an export is closed or
revoked, the engine tells the peers that hold authority over it, and a peer that does not
answer within `RPC_REVOKE_BOUND_MS` has its session broken. Two threads share the engine
behind one lock: the local thread accepts calls on the proxy endpoints (`ipc_accept_v2`)
and the link thread reads datagrams and keeps time. The link is UDP to the one peer
`RPC_PEER_ADDR`:`RPC_UDP_PORT`; datagrams from any other source are dropped.

Every session is authenticated: a Noise IK handshake with the static keys the topology pins
in its `peer` rows (its view region, `MemObj inspect.rpc`), and every later frame is sealed. The node's static key is
derived from the board seed and the measurement of this image, issued by the kernel on its
`linkkey` endpoint; the ephemeral keys come from `entropy`. A row without both grants runs
nothing, and an image other than the one a key was pinned for gets another key and no
session.

With Kconfig `RPC_QUIC` the one peer is the `rpcquic` relay on the same host: a std program
that carries the sealed frames between the two nodes on QUIC streams, so the QUIC stack and
its TLS are in a process whose only authority is the network and the entropy pool, not in
the one that holds the lend rights. It takes no arguments; the node with the lower id dials
`RPC_PEER_ADDR`:`RPC_QUIC_PORT`, the other listens, and the relay binds `RPC_QUIC_RELAY_PORT`
and answers `rpcsrv` on the host's own address only.

## zenohd and mcpd

Source: `userspace/services/zenohd/src/main.rs`, `userspace/services/zenohd/src/gw.rs`,
`userspace/services/zenohd/src/route.rs`, `userspace/services/mcpd/src/main.rs`,
`userspace/services/mcpd/src/bridge.rs`, `userspace/services/mcpd/src/catalog.rs`,
`userspace/services/mcpd/src/warrant.rs`, `userspace/services/mcpd/src/receipt.rs`.

Both turn an external request into one warrant-guarded IDL call that the kernel admits or
refuses, and answer with the decision record that is the receipt. Neither adds an
authority check of its own, so neither can grant a right. Both are single-threaded and
redial a lost link with a growing wait.

**zenohd** is a Zenoh client of one router (TCP to `ZENOH_ROUTER_ADDR`:`ZENOH_ROUTER_PORT`).
It declares queryables from the exports named by Kconfig `ZENOH_DECISIONS_KEY`; a query
whose last key chunk names an op (`azos/dec/get` is `Decisions::get`) is turned into a
warrant (an attenuated, badged, call-only copy of the export's endpoint that lapses with the
query), one call through it, and a reply whose payload is little-endian `u64` words: a code
(`SERVED`, `REFUSED`, `BAD_REQUEST`, `FAILED`, `BUSY`), the receipt id, the receipt's rule
and verdict, the IDL status, then the op's reply words. With a topic prefix configured it
also publishes every decision record under `<prefix>/<rule>/<verdict>`, rate limited, and
counts the records overwritten before they could be read. It is not the warrant transport
between nodes (that is `rpcsrv`). It opens no file; its configuration is Kconfig.

**mcpd** serves the Model Context Protocol over a TCP stream. The native stack has no
listening socket for ring 3, so it dials out (`MCP_PEER_ADDR`:`MCP_PORT`) and plays the MCP
server role over the stream. Its tools come from the IDL op tables: an op of an exported
interface becomes the tool `<interface>.<op>` when it declares its delivery
(`#[idempotent]`, `#[at_most_once]` or `#[once_only]`), takes no capability, and has a number
the warrant's op mask can name. Every `call` request to a tool needs a warrant (a macaroon,
`azos_rpc::wire::Token`) that names the op and expires. An op that cannot be undone
(`#[once_only]`) is only proposed by its tool; a human confirms it with a one-shot warrant
and the agent commits it once. The root of the warrants is the image's own key derived from
the board seed (`LinkKey::node_key`), which never leaves the task; without a board seed the
bridge refuses to run.

| Tool | Who may call it |
|---|---|
| `<interface>.<op>` | an agent holding a warrant naming the op |
| `azos.confirm` | a human, with the one-shot confirmation warrant |
| `azos.commit` | the agent, to run a confirmed proposal |
| `azos.grant_agent`, `azos.grant_confirm` | the operator, whose warrant is printed on the console at boot |

Its view region (`MemObj inspect.mcp`) lists the endpoints its row holds with the call
and the lend right; the bridge keeps those its own table holds so.

## ptpd

Source: `userspace/services/ptpd/src/main.rs`, `userspace/services/ptpd/src/port.rs`,
`userspace/services/ptpd/src/wire.rs`, `userspace/services/ptpd/src/bmc.rs`.

An IEEE 1588 slave over UDP (multicast group 224.0.1.129, ports 319 and 320) with software
timestamps. It follows the best master it hears, measures the wall clock against it, and
offers each measurement to the kernel's `Clock` interface (`Clock::sample`, source PTP);
the kernel's discipline decides whether to filter, slew or step. The row grants `W` on
`clock` and its view of the `[clock]` row (`MemObj inspect.clock`). The domain is the `ptp_domain` of the
topology's `[clock]` row; a node whose row declares none takes no part and the program
says so and ends. 802.1AS over raw Ethernet is not served, because a packet socket belongs
to the kernel.

## audiod

Source: `userspace/services/audiod/src/main.rs`, `userspace/services/audiod/src/server.rs`,
`userspace/services/audiod/src/mixer.rs`; host tests `tests/host/audiod-tests`.

The audio server serves the `Sound` interface (`azos_devif::sound`) on `endpoint.audio`, in
front of the kernel's `sound.0`. A client opens a stream with the memory objects it made
(a `ready` queue, a `done` queue and an arena of periods, lent to the server: a copy of
each capability, so the client keeps its own and its mappings, which a move would take
with it) and the periods never cross a call; the server mixes the running streams into
the **one** playback stream it holds on the device and returns each period on `done`.

* **The device's format.** A stream names the device's rate and channel count and signed
  16-bit samples, or `open` answers `UNSUPPORTED`; nothing is resampled. A client period
  is cut to the device period (1024 frames), whatever length the client chose.
* **The mix.** A saturating 32-bit sum, each live stream at the gain `2 / (n + 1)` for `n`
  live streams (1.0 alone). A stream that runs dry underruns alone: silence from it for
  the rest of the pass, `PERIOD_XRUN` on the next period it gets back, the device and the
  other streams untouched.
* **The device stream** is opened when a stream first runs, kept two periods ahead, and
  drained and closed when none does.
* **Who a stream belongs to.** The server sees only the badge of the capability a call went
  through, so a client derives a badged copy of its endpoint capability (the row grants
  `W` with `transfer = true`, which gives `DUP`) and calls through it: one badge, one
  stream. A call with badge 0 is refused.
  The badge is the holder's choice, which is enough to tell cooperating clients apart and
  not hostile ones. A running stream that gives the mixer nothing for 3 s is closed, and
  one nobody called for 60 s.
* **Capture is lent, never mixed, and the client's to ask.** The client's three objects are
  handed to the kernel's `sound.0` as they are; the kernel's gate (the `mic` effect of **the
  client's** scheduler class, Kconfig `AUDIO_CAPTURE`, the microphone indicator) decides, and
  writes the `audio-capture` decision record for every attempt that reaches it, which ring 3
  cannot. The server asks for nobody but its clients, and uses none of its own for them. The client's authority travels
  with the open as the **warrant of the call the server is serving** (the handle
  `SYS_IPC_ACCEPT_V2` returned), which `Sound::open` carries as `on_behalf`: the kernel gave it to
  the server's main thread alone, it names the task that made the call, and it ends with the
  reply, so it cannot be kept or replayed. The kernel resolves it to that task, decides the
  effect on its class, records it as the subject and names it in the indicator
  (`[AUDIO] microphone LIVE: ... tid N`); the server's class is never consulted. A client without
  the effect is refused (`REFUSED`, reaching it unchanged; the record names it, with reason
  `no grant`) and takes nothing from the server. Every client passes `on_behalf` 0; the server
  refuses a nonzero one (`BAD_ARGUMENT`) and never forwards it. The server prints one console
  line per attempt, naming the badge. A badge has one stream of either kind: a second `open` of
  the other kind is `BUSY`. Limits: the server pairs a warrant with that call's objects, which
  the kernel does not check; and the client's class is that of the topology row its calling
  thread was seeded from, so only the image's main thread has one; and the kernel does not stop a
  server that went wrong from calling `sound.0` with `on_behalf` 0, which is decided on the
  server's own class (the effect unless an `[envelope]` `mic` row contains it): a deployment that
  must rule that out gives the audio server's row a class with a contained `mic` row.
* **Two threads.** The main thread accepts calls (the endpoint's `READ` grant is stamped
  with it) and makes every capture call, because the kernel binds a stream to the thread
  that opened it, and the warrant of the call is held by the thread that accepted it; the pump
  thread mixes.
* **Who holds what time.** The row is a best-effort service with no profile: the main
  thread, which accepts calls, has no budget and needs none. The pump thread asks for its
  own deadline reservation when it starts (`SYS_SCHEDCTL`, class DL, on the row's `time`
  warrant: Kconfig `AUDIOD_PUMP_RUNTIME_US` every `AUDIOD_PUMP_PERIOD_US` at band level
  `AUDIOD_PUMP_LEVEL`, placed by admission on the hart the pump runs on), and the main
  thread serves nothing until it has the answer. Admitted, the server prints
  `[audiod] mixer: deadline reservation of ...`; refused, it prints
  `[audiod] mixer: no deadline reservation (refused: -N): no playback` and answers every
  playback `open` `UNSUPPORTED` rather than mix at a real-time level with no budget (capture
  is unaffected). Neither thread ever spins: the lock they share is a futex word the one
  that finds it held sleeps on, the pump sleeps on the clock or a futex word between bounded
  passes, and an accept that returns no call sleeps.

`toolbox beep` goes through the server when its row holds `endpoint.audio` and straight to
`sound.0` otherwise; with the server the toolbox row holds no `sound.0`, since the device
has one holder.

## vmmd

Source: `userspace/services/vmmd/src/main.rs`, `userspace/services/vmmd/src/life.rs`,
`userspace/services/vmmd/src/model.rs`; see [virtualization.md](virtualization.md) for the
interfaces and the device models.

The ring-3 virtual-machine monitor. The kernel's hypervisor core owns what only the kernel
can (stage-2 tables and the vCPU threads); `vmmd` serves everything a guest does with a
device. The guest holds no warrant, but `vmmd`'s backends do: the disk is a file opened
through the directory capability of its row, the console is the console this task writes,
the NIC is a ring pair. Its row holds `READ|EXEC` on `vm.0`, `READ|WRITE|EXEC` on each
`vcpu.0.k`, `RW` on `/fat/VM`, and `ROOT_RO`: no motor, pin or network authority.

## lxsrv and lxrt

Source: `userspace/services/lxsrv/src/main.rs`, `userspace/services/lxrt/src/main.rs`,
`userspace/lib/linux_rt/src/lib.rs`, `crates/core/lx-loader`.

`LXSRV.ELF` is the Linux driver server (Kconfig `LINUX_DRIVERS` with `LX_SERVER_SKELETON`).
It reads a module from the volume, checks its `.modinfo`, asks the kernel to verify the file's
hash against the digest table built into the kernel image (`DOMAIN_MODULE_VERIFY`, which
grants a one-shot token), lays the module out in anonymous regions and relocates it
(`crates/core/lx-loader`), asks the kernel to flip the text region from read-write to
read-execute (`DOMAIN_MODULE_MAP_X`, never both), and calls its init. A forged token, a range
larger than the verified module and a reused token are each refused. Its row holds `READ` on
`entropy` and `ROOT_RO`, and no actuator.

The Linux runtime image (`lxrt`, Kconfig `LINUX_RUNTIME`) has no row: it is
`userspace/lib/linux_rt` over the native ABI, linked at the runtime window
(`azos_abi::foreign`) and embedded in the kernel image. The kernel maps it into every Linux
process at spawn and starts the process there; each Linux system call the program makes
traps into the runtime's entry (registered with `SYS_FOREIGN_ENTRY`), which answers it or
maps it onto native calls. It runs on the program's stack and is built without floating
point (on x86_64, on rustc's soft-float `x86_64-unknown-none`, with no SSE). On x86_64 the
trapped call is Linux's x86-64 one: `azos_linux_abi::x86_64` translates its number and
argument registers to the call the runtime answers, and the runtime writes the x86-64
`struct stat`, `uname` and `sigaction` layouts.

## infsrv

Source: `userspace/services/infsrv/src/` (`lib.rs` is the broker, `main.rs` the program),
`crates/core/devif/src/infer.rs`, `userspace/lib/ml/src/bundle.rs`; its client in the kernel is
`kernel/src/behavior_ml.rs` and `kernel/src/behavior_infer.rs`. Tests: `tests/host/infsrv-tests`. The image is still called
`MLSRV.ELF`: the topology row, the seccomp profile and the disk-image recipes name it, and are
renamed together.

The ring-3 inference service.

It serves the `Infer` interface (`azos_devif::infer`) on an endpoint, with two
more interfaces beside it that the header of each request tells apart: `Decisions`, which reads
back the receipts, and `InferLog`, which lends the verdict log. A client reads the receipts of its
own badge only, and the log it is lent is an object of its own context: neither shows another
context's refusals or energy use. Models are the signed `.MBL`
bundles (`tools/make_mbl.py`) on the FAT volume: every `/fat/*.MBL`, up to `INFSRV_MODELS`. A
bundle's manifest is verified with the topology key before any field of it is read (a bundle
carries the cost table the admission believes, so there is no switch to turn that off); a
variant's blob is kept only if the machine has its backend, it fits the blob arena
(`INFSRV_BLOB_KIB`), its SHA-256 is the manifest's and it is a two-layer MLP of the manifest's
tensor sizes. The backends run in process: `cpu-ggml` (the sequential dot product of
`azos_ml::ggml_nano`) on every ISA, and `rvv` (the same layers over the vector unit) on riscv64
when the vDSO hardware-capability word says the hart has V and the vector dot product agrees
with the sequential one at start-up. Both are `BACKEND_GGUF` of the bundle; which kernel runs a
variant is the machine's business and a vector kernel only shortens a run.

For each call the broker walks the model's fallback list and takes the first variant whose blob
is loaded, whose working memory fits (`INFSRV_WORK_KIB`), whose signed worst-case time fits the
time left to the caller's deadline and whose signed energy fits what is left of the context's
quota (`INFSRV_ENERGY_QUOTA_UJ` per `INFSRV_ENERGY_WINDOW_MS`; the context is the badge of the
endpoint capability, at most `INFSRV_CONTEXTS` of them); with the `low-energy` hint, the one of
lowest signed energy among those. When none fits the call is refused now (`UNSUPPORTED`, `BUSY`
or `REFUSED`, by the check the best candidate failed) and the refusal is a decision record of
Rule `accel-admission` whose id, the receipt, goes back in the verdict. An admission is recorded
when it changes the variant a model runs on, not on every call. The records are the service's
own journal (a ring-3 server cannot write the kernel's), served as a `Decisions` object so a
receipt is read back with `azos_decisions::fetch`. The energy of the chosen variant is reserved
when it is admitted; a run that took longer than its signed worst case is charged the excess at
the variant's own rate, and the energy the caller is told is what it was charged. `attach` and
`detach` (the queue form of the interface) are `UNSUPPORTED` until a queue is driven.

The blob arena is a volatile memory object (`SHM_ATTR_VOLATILE`, `Documentation/memory.md`), not
`.bss`: the weights are files on the volume, so the service can make them again. Between calls
it is marked droppable (`MemCtl::set_volatile` on the `memctl` endpoint, `WRITE`) and while a call
runs it is held (`set_nonvolatile`); when the system took it back under pressure, the call that
finds out forgets the models, takes a new object and loads the bundles again (every signature and
digest is checked again), then runs. The reload is out of the caller's deadline: it happens
before the admission reads the clock. The contexts' energy accounts and the receipts are not
touched. With no reclaim in the build (`MM_RECLAIM_OFF`) the object is never taken. The system
purges a droppable object only when it as a whole is short of frames; a Domain that is over its own
mark is told on its memory-pressure port instead (`PORT_SRC_PRESSURE`), which the service makes at
start and reads where a call ends: a rise of the level (warning, or warning to critical) gives the
arena back at once, and the next call loads it again. A rise is reported once, so a level that
stays up does not make every call reload. An idle service hears it at its next call.

The latest verdict of each context (`azos_rings::Log<Verdict, 1>`) is published in a memory
object the service makes; `InferLog::log` lends it read-only and names the caller's cell, and a
real-time reader polls it with no call (`infsrv::verdict::LogReader`).

**The behavior loop is a client like any other.** The kernel's behavior task starts the service
(supervised) and calls its `Infer` interface once per cycle, on `endpoint.infer`, through a
capability the kernel mints for it with the badge of its own context: the model is the signed bundle
`/fat/BEHAVIOR.MBL` (`tools/make_mbl.py` from `policy.gguf`; the kernel names it by its model
reference, which the build checks), the input is `[front / 1000, right / 1000, 0.5, 0.9]` as `f32` in a
memory object, the output the three logits in another, lent to the service for the call (so the
loop keeps them and reads the answer after the reply), and the deadline is
`ML_REPLY_TIMEOUT_US` (10 ms). The loop does not make the call itself: the kernel's endpoint call
waits for as long as the server takes, so a task of its own, `ml-infer`, makes the calls one at a
time and the loop waits for it with a timer. Every way a call can end that is not a class is a
missing verdict and L1 holds STOP (`domains/robot/behavior/src/ml_link.rs`): a refusal
(`REFUSED` is `Late`, `NO_RESOURCE`, `NOT_READY`, `BUSY` and `UNSUPPORTED` are `Unavailable`, any other
code `Malformed`), a deadline that passed, a service that is not there, a reply of another model
than the one asked for, or logits that are not numbers. The reply's model reference, variant and
backend travel with the verdict into the trajectory record of the motor command
(`azos_robot::ModelRecord`). The start-up self-test classifies the policy file
`/fat/POLICY.GGF` once its signature `/fat/POLICY.SIG` (a `DSIG`) verifies (Kconfig
`INFER_MODEL_SIG_REQUIRED`). Its row is `soft_rt` at priority 16 and grants `READ` on
`endpoint.infer`, `WRITE` on `memctl` and `ROOT_RO`; it serves on its main thread. It runs
hard-float on aarch64.

## brain_client and reflex

Source: `userspace/services/brain_client/src/main.rs`,
`userspace/services/brain_client/src/link.rs`, `userspace/services/reflex/src/main.rs`.

Two programs of the robot domain (Kconfig `USE_ROBOT`). `BRAINCLI.ELF` reads the sensors
through syscalls, builds framed sensor packets, sends them sealed over TCP to a brain server
(every connection begins with a handshake in `link.rs`; the peer speaks first and the client
answers as responder), receives actuator commands and applies them to the `motor` endpoints.
`REFLEX.ELF` reads the rangefinder and the IMU and overrides motor commands when danger is
detected (extreme tilt, then an obstacle too close, then a warning distance), whether or not
the brain link is up. The topology holds a row for each (with `GPIODRV.ELF`, the GPIO driver
of `userspace/drivers/gpio_drv`). The rows carry no capabilities of their own beyond
`ROOT_RO` on `BRAINCLI.ELF`: the `autorun` key of `CONFIG.INI` picks one of the three to
run, and the grant a running one gets comes from the generic `autorun` row
(`find_task(b"autorun")`).
