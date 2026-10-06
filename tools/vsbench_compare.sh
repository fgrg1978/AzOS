#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# vsbench: run the same ring-3 work on AzOS and on Linux/riscv64, under the
# same QEMU, and compare what was MEASURED — not how fast it was.
#
# ## Why this exists
#
# The hardware gate is conditional on "vsbench with parity against Linux or a
# justification per measurement". Until 2026-09-07 that condition was checked
# by hand, once. Nothing re-ran it, and the Linux half was not even built
# by `make userspace` — long enough for its `fork_exit` lane to accumulate a
# comment saying the reap "should be taken back in" and dead code marked "kept
# for when this lane measures the full life cycle again".
#
# ## What is asserted, and what deliberately is NOT
#
# **NOT asserted: timings, ratios or thresholds.** Five runs of the same AzOS
# binary on 2026-09-07 spanned 246,450-332,975 ns/op on `fork+exit` alone —
# about 35% — and the "x floor" ratios moved 73x-184x because the floor itself
# oscillates. A threshold over that produces false reds, and a false red in a
# gate is worse than no check: it trains the reader to ignore it.
#
# `switch-loaded` was bimodal — 33,964 / 32,416 / 2,822 ns/op across three runs
# of the same binary on 2026-09-07 — and the note here used to guess at the
# host being busy. **ATTRIBUTED on 2026-09-10, and it was not the host.**
#
# Linux is measured in the same runs on the same machine and stayed inside
# 3,460-4,738 while AzOS spanned 3,276-59,926. A busy host moves both.
#
# The low mode is the broken one: the lane's four "competitors" were not
# competing, so it measured an unloaded yield under a loaded label. Reproduced
# deliberately by making the peers return without yielding (3,602 against a
# 3,336 unloaded yield), and then caught in the wild 1 boot in 12 — the lane
# refused at 3,280 against a 3,418 unloaded yield.
#
# **ATTRIBUTION ATTEMPTED AND INCONCLUSIVE (11-09).** If hart placement were
# the cause — four peers, four harts, and the measurer sometimes alone on its
# own — then FEWER harts would mean more collisions and fewer refusals. Ten
# boots at `-smp 2` and ten at `-smp 4` both gave zero. Counting the earlier
# capture that is 1 in 22 at `-smp 4` and 0 in 10 at `-smp 2`: a base rate near
# 4-8% cannot be separated from zero at that sample size, so the rate
# comparison decides nothing either way. Attributing it needs ~100 boots per
# configuration or a probe printing each forked peer's hart. Not chased,
# because the guard already keeps the bad measurement out of the number, and
# the lane is out of the comparison column anyway.
#
# **THE ~33 k / ~50 k SPLIT IS PLACEMENT, AND IT IS MEASURED (13-09).** A
# different bimodality from the refusals above: both modes are healthy runs
# with 500 real switches. `SYS_TASKINFO` now reports the caller's hart, and the
# lane prints where the measurer and each peer ran (`switch-loaded hart:`),
# outside every measured batch. Over 20 boots of one frozen binary the mode was
# exactly k, the number of peers on the measurer's hart: k=1 → 31,454-34,878
# ns/op (4 boots), k=2 → 47,710-52,878 (16), no overlap, no task changed hart.
# Two tasks per round against three is the 1.5x between the modes. So a
# `switch-loaded` number is only meaningful next to its k.
#
# That capture also corrected the first guess. The run that first showed the
# fast value ALSO had `ipc-roundtrip` at 998,290 ns and no `udp-roundtrip`
# line, which read like a boot with forked processes broken; the captured
# recurrence had both lanes normal. Coincidence, not signature.
#
# The lane now refuses to print a number at or below the unloaded yield and
# always reports the ratio to it — see `loaded_switch_lane`. A healthy AzOS
# run is 10-19x; Linux is legitimately ~1.4x, which is why the check is an
# impossibility and not a threshold.
#
# **AND THEN THE COUNTERS SETTLED IT (11-09).** Both sides now report real
# context switches — AzOS through `SYS_TASKINFO`, Linux through `getrusage` —
# and `switch-loaded` turns out not to be comparable AT ALL:
#
#     azos:  500 voluntary + 3 preempted over 500 yields
#     linux:     0 voluntary + 0 preempted over 500 yields
#
# Linux's `sched_yield` re-elects the running task when nothing else is
# runnable on its CPU, so its 5,370 ns was the cost of LOOKING and ours was 500
# real switches. Do not read that lane as a context-switch comparison in either
# direction.
#
# `ipc-roundtrip` is the lane that compares, because both sides BLOCK there and
# both must switch — measured 1010 switches against 1000 over the same 500
# round trips:
#
#     azos:  45,059 ns per switch
#     linux:   74,056 ns per switch
#
# So on the only lane where the question is well posed, AzOS is ~1.6x FASTER
# per context switch, not 11x slower.
#
# **WAVE 15: THE 11-09 COUNTERS WERE AT `-smp 4`; AT `-smp 1` THE REASON
# CHANGED, AND THE LANE STAYS OUT FOR A DIFFERENT ONE.** At one hart Linux
# does switch (0 voluntary + 479-500 preempted over 500 yields), but the
# competitors' own stamps (see `loaded_switch_lane`) show what one op holds:
#
#     azos:  4.00 competitor yields per measurer yield (round-robin of five)
#     linux: 0.50-0.95 (EEVDF re-picks the measurer after about one)
#
# so `switch-loaded` is ~5 yields of work on AzOS and ~2 on Linux. And both
# sides had a sixth task in the window: `udp-roundtrip`'s echo, left polling
# `recv` + yield for the rest of the run (now stopped, `Net::net_stop_echo`;
# AzOS's `SWITCH_CENSUS` named its slot). The comparable number is
# `ctxsw-loaded`: the same window divided by the context switches inside
# it, on both kernels.
#
# **`switch-loaded` IS THEREFORE EXCLUDED FROM THE COMPARISON COLUMN** (see
# `LANES_NOT_COMPARABLE` below) and kept only as a AzOS-side number. It is
# still worth having: it is the one measure of what a context switch costs this
# kernel under load, and its refusal guard caught a bad boot 1 run in 12. What
# it is not is a number to put beside Linux's, and a lane that does not compare
# sitting inside a comparison table is an invitation to cite it.
#
# Asserted instead:
#   1. Both sides RUN to completion — asserted as "the last lane is present",
#      not as a marker line; see `completion_lane` for the run that showed why.
#   2. Neither side reports a lane failure (`FAIL rc=`).
#   3. Every lane AzOS measures has a Linux counterpart — "parity or a
#      justification per measurement". The
#      justification is an explicit table, `justified_azos_only` below: one
#      lane label and a one-line reason per row, for a lane Linux has no object
#      to measure. Consulted in both directions:
#        a. a AzOS (gate) lane missing on Linux and NOT in the table fails;
#        b. a table row for a lane Linux DOES report fails (stale: a number
#           now exists, and a reason saying it cannot is false);
#        c. a table row for a lane the gate column did not measure fails
#           (stale: the lane was renamed or removed, and the row justifies
#           nothing).
#      The justified lanes and their reasons are printed on every run, and the
#      table shows `justified` in their Linux cells rather than a bare `-`.
#   4. The gate AzOS column booted a `bench-minimal` kernel: its own log
#      shows the scheduler's banner (see "Two AzOS columns" below).
#
# (1)-(3) are asserted on the gate column; the product column's are reported.
#
# (3) is the one with teeth. A lane silently dropped from either side is
# exactly how "we have parity" rots into a claim about a build nobody runs. The
# direction is deliberate: Linux may measure MORE than we do (it has `getcpu`,
# which this kernel offers by neither path and says so in its own output), but
# a AzOS lane with no counterpart means the comparison stopped covering it.
# The table exists so that "no counterpart" is a decision written down per
# lane, not a gap: wave 6 (2026-09) added 27 AzOS-only lanes, the gate went
# red on all of them, and 24 got a real Linux counterpart (`futex`, a
# `MAP_SHARED` SPSC ring, `getrusage`, a pipe, `clock_nanosleep`, `io_uring`;
# see `userspace/bench/vsbench/src/abi_linux.rs`). Only the three below are rows.
#
# The numbers are printed side by side for a human to read. That is what they
# are for.
#
# ## Two AzOS columns (owner decision 2026-09-14)
#
# The same VSBENCH.ELF, from the same disk image, is booted on two kernels,
# each built here into its own cargo target directory:
#
#   GATE:azos-min  `--features qemu,bench-minimal`: `idle` and `autorun` run,
#                    every other task is parked. The hardware gate reads this
#                    column against Linux, which also runs a single process.
#   azos-product   `--features qemu`: the full daemon set, published beside
#                    it so what the daemons cost is visible. Its findings are
#                    printed and do not change the exit status.
#
# The gate column is REFUSED unless its own log carries the banner the
# scheduler prints the first time it parks a task under `bench-minimal`
# (`task_create_affinity`, crates/core/sched/src/scheduler.rs). A product log that
# carries the banner fails the run as well: that would be a second
# bench-minimal kernel under the product label. The log rather than the image,
# because the banner in the log shows the feature reached the scheduler of the
# kernel that actually booted.
#
# ## The Linux image is an environment decision
#
# This script neither downloads nor builds a `riscv64` Linux. Point
# `VSBENCH_LINUX_IMAGE` at one; the default is the image this script
# records below. Absent, this fails — unless `CI_SKIP_VSBENCH_LINUX=1`, the same
# shape `CI_SKIP_QEMU=1` already has, so a machine without the reference
# kernel can still run the rest of the gate without the skip being silent.
#
# ## The Linux + seccomp column (`VSBENCH_SECCOMP=1`)
#
# Owner decision 2026-09-14: AzOS runs vsbench under its image profile, so
# Linux gets a column under an equivalent filter too, beside the unfiltered
# Linux column, which stays.
#
# The benchmark is the SAME Linux ELF, unmodified. `tools/linux_seccomp_launch`
# is `/init` in its initramfs: it sets `PR_SET_NO_NEW_PRIVS`, installs a
# seccomp-bpf allow-list of exactly the syscalls vsbench's Linux side issues
# (`tools/linux_seccomp_launch/src/allow.rs`, plus the launcher's own
# `execve`), default `SECCOMP_RET_KILL_PROCESS`, and execs `/vsbench`. The
# filter survives `execve` and every forked peer inherits it.
#
# A syscall missing from the list KILLS instead of returning an errno, so it
# cannot print a number. How a kill shows up in this script's output:
#   - `[VSBENCH-SECCOMP] launcher FAIL:` — the filter could not be installed or
#     `/vsbench` could not be exec'd. The launcher never execs vsbench
#     unfiltered.
#   - PID 1 killed (vsbench itself): `filter installed` with no lanes, or not
#     all of them, after it. The kernel's `Attempted to kill init!
#     exitcode=...` value is printed for the reader and not matched: which
#     value SIGSYS produces for init on this kernel is not verified.
#   - A forked peer killed: init does not panic; the parent's lane reports
#     `FAIL rc=` or has no number.
#   - Either way, a lane the unfiltered Linux column measured in the same run
#     and this column did not is reported as pointing at the filter: same
#     binary, same kernel, same QEMU.
#   - An `audit: type=1326 ... syscall=<n>` record names the call when the
#     kernel emits one. Printed if present, not relied on.
#
# Off by default. Its failures are reported and do not change the exit status
# unless `VSBENCH_SECCOMP_STRICT=1`. `VSBENCH_SECCOMP_CANARY=1` passes
# `VSBENCH_SECCOMP_CANARY=1` on the guest command line: the launcher then calls
# `getppid` (173, not listed) after installing the filter, and that run passes
# only if the launcher dies there.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QEMU="${QEMU:-/opt/homebrew/bin/qemu-system-riscv64}"

# ── VSBENCH_ICOUNT=1: measure instructions instead of nanoseconds ───────────
#
# WHY THIS EXISTS. The wall-clock lanes cannot resolve the difference they are
# most often asked about. Five runs of the same two binaries on 2026-09-16, on
# a host at load 1.3-6.8, put `syscall-floor` anywhere from 11% BELOW Linux to
# 14% ABOVE it -- and an earlier single run of that spread had been recorded as
# a "+12% regression" and chased. The lane was measuring the host.
#
# `-icount shift=0` makes the vCPU advance virtual time by one unit per
# instruction, so a lane's "ns/op" becomes an instruction count: deterministic,
# identical across runs, and blind to whatever else the Mac is doing. The same
# two binaries then read 334 (AzOS) against 237 (Linux) every time.
#
# WHAT IT IS NOT. It is not a speed measurement: it counts instructions, not
# the cost of each one, and QEMU's own translation cost disappears from it. A
# lane that waits on a device or sleeps is distorted -- `sleep=off` keeps the
# guest running rather than idling to the next deadline, which is right for the
# syscall lanes and wrong for anything that measures waiting. Use it to compare
# code paths, and the ordinary run to compare times.
#
# A plain string, NOT an array: this file runs under `set -u`, and
# `"${arr[@]}"` on an EMPTY array is an unbound-variable error in bash 3.2 --
# which is what `#!/usr/bin/env bash` finds on this Mac. The array version
# worked when the mode was on and would have killed every default run.
VSBENCH_ICOUNT="${VSBENCH_ICOUNT:-0}"
ICOUNT_ARGS=""
if [ "$VSBENCH_ICOUNT" = "1" ]; then ICOUNT_ARGS="-icount shift=0,sleep=off"; fi

# ── VSBENCH_SMP: hart count, and why 1 is the only DETERMINISTIC setting ─────
#
# `-icount` alone is not enough. It makes a lane reproducible only when the
# lane's cost does not depend on WHEN another hart picks up work, and at the
# default `-smp 4` the process lanes do. Measured 2026-09-18, three runs of the
# same unchanged binaries at `-smp 4`: `syscall-floor` read exactly 314/237
# every time (one hart, tight loop), while `fork+exit` on the LINUX side --
# nothing changed between runs -- produced 122,410 / 2,259,292 / 3,661,717, a
# 33x spread with no failure in any run. An 18% "improvement" measured against
# that is noise, and was.
#
# `VSBENCH_SMP=1` with `VSBENCH_ICOUNT=1` is bit-exact. The same three lanes,
# twice: fork+exit 293,982 / 293,982, fork+exit+wait 402,202 / 402,202,
# ipc-roundtrip 4,021 / 4,021. That resolves a SINGLE instruction, which is
# what an A/B on a kernel path actually needs.
#
# WHAT CHANGES WITH IT, and why it is not the default. One hart is a different
# machine, not a quieter one: absolute numbers move a long way (AzOS's
# `ipc-roundtrip` 10,428 -> 4,021), and a lane whose cost is a POLLING LOOP
# inverts, because the thing it waits for can no longer run beside it --
# Linux's `fork+exit+wait` goes 587k -> 2,112,380 and hands AzOS a 5.2x
# "win" that is an artifact of the wait, not of the fork. So: `-smp 4` stays
# the default and every recorded baseline keeps its meaning; use
# `VSBENCH_SMP=1` to A/B a change against ITSELF, and never to quote a
# AzOS-vs-Linux ratio on a lane that polls.
VSBENCH_SMP="${VSBENCH_SMP:-4}"

# ── VSBENCH_RING_DET: the ring lanes again, under one TCG thread and -icount ─
#
# Owner decision 2026-09-28 (wave 9 INV, question 4). `ring-pingpong` in the
# gate column read ~550,000 ns/op against ~148,000 in the product column, same
# kernels, host load ~40. Measured: under MTTCG (the default) each exchange
# wakes a HALTED vCPU of the parked gate column, and that host-thread wake
# scales with host load; under `-accel tcg,thread=single` the gap closed, and
# under `-icount` the gate column read 14,001 against the product's 218,521.
# The lane measured the host. The product column does not show it because its
# daemons keep those vCPUs running.
#
# So the gate column's ring lanes (`ring-*`, the shared-memory SPSC ring,
# `ioring-*`, the submission ring, the driver-request pair `drv-call` /
# `drvring-*` and `frame-stream`, wave 11) are measured a second time, on a second
# boot of the SAME kernel-min kernel and the SAME Linux initramfs, both under
# `-accel tcg,thread=single -icount shift=0,sleep=off` at the same `-smp`
# (`-smp 1` would put client and server on one hart and change what the lane
# measures). Their numbers are instruction counts, printed in a table of their
# own, and assertions 1-3 hold for that pass too: both sides reach the last
# lane, no lane fails, every AzOS ring lane has a Linux counterpart.
# `ioring-tmr` stays out of the comparison for the reason `LANES_NOT_COMPARABLE`
# gives. The wall-clock table keeps its ring rows; read this table for them.
# `-icount` already runs one TCG thread; `thread=single` is written out so the
# line says what it measures. `VSBENCH_RING_DET=0` skips the pass; it is
# skipped anyway when `VSBENCH_ICOUNT=1`, where every lane already runs so.
VSBENCH_RING_DET="${VSBENCH_RING_DET:-1}"
RING_DET_ARGS="-accel tcg,thread=single -icount shift=0,sleep=off"
RING_LANES_RE='^(ring-|ioring-|drvring-|drv-call|frame-stream)'
LINUX_IMAGE="${VSBENCH_LINUX_IMAGE:-$HOME/devel/vms/riscv/Image}"
WAIT_SECS="${WAIT_SECS:-60}"
WORK="${VSBENCH_WORK:-$REPO_ROOT/build/vsbench-compare}"
CARGO="${CARGO:-cargo}"
VSBENCH_SECCOMP="${VSBENCH_SECCOMP:-0}"

# ── VSBENCH_LANES: run only some sections, on every side (wave 15) ──────────
#
# A comma list of section keys (see `Lanes` in
# userspace/bench/vsbench/src/bench_core.rs): ipc, mem, proc, thread, vdso,
# ioring, shell, timer, net, switch. The floors and the unloaded yield always
# run. Unset (the default) changes nothing: no file is added to the AzOS disk
# and no word to the Linux command line. Set, AzOS reads it from
# /fat/VSBLANES.TXT in its own disk copy and Linux from init's environment.
# For iterating on one change only: a filtered run is not a comparison of the
# suite, and the seccomp column (whose check is "every lane the unfiltered
# column measured") is refused with it.
VSBENCH_LANES="${VSBENCH_LANES:-}"
if [ -n "$VSBENCH_LANES" ]; then
    printf '%s' "$VSBENCH_LANES" | grep -qE '^(ipc|mem|proc|thread|vdso|ioring|shell|timer|net|switch)(,(ipc|mem|proc|thread|vdso|ioring|shell|timer|net|switch))*$' \
        || { echo "vsbench: VSBENCH_LANES=$VSBENCH_LANES: want a comma list of ipc,mem,proc,thread,vdso,ioring,shell,timer,net,switch" >&2; exit 1; }
    [ "$VSBENCH_SECCOMP" = "1" ] && { echo "vsbench: VSBENCH_LANES and VSBENCH_SECCOMP=1 do not mix" >&2; exit 1; }
    echo "vsbench: lanes filtered to: $VSBENCH_LANES" >&2
fi

# ── VSBENCH_BENCH_FEATURES: extra cargo features of the vsbench binary ─────
#
# Both sides, for the lane canaries (e.g. `switch-peer-canary`); empty by
# default. The Makefile keeps the AzOS ELF's feature set in a stamp
# (build/vsbench.features), so the next default run rebuilds it.
VSBENCH_BENCH_FEATURES="${VSBENCH_BENCH_FEATURES:-}"
export VSBENCH_FEATURES="$VSBENCH_BENCH_FEATURES"
[ -n "$VSBENCH_BENCH_FEATURES" ] && echo "vsbench: CANARY/diagnostic bench features: $VSBENCH_BENCH_FEATURES" >&2
VSBENCH_SECCOMP_STRICT="${VSBENCH_SECCOMP_STRICT:-0}"
VSBENCH_SECCOMP_CANARY="${VSBENCH_SECCOMP_CANARY:-0}"
# Cargo target directories, one per artefact this script builds:
# `azos-bench-minimal`, `azos-product`, `vsbench-linux`, `seccomp-launch`.
# NOT the repository's default `target/riscv64imac-unknown-none-elf/release`,
# which other builds and scenarios share, and NOT `userspace/bench/vsbench/target`,
# where `make` builds the AzOS VSBENCH.ELF. Not under `$WORK` either, which is
# wiped on every run.
BENCH_TARGET="${VSBENCH_TARGET:-$REPO_ROOT/target/vsbench-compare}"
LINUX_RUSTFLAGS="-C code-model=medium -C target-feature=+zaamo,+zalrsc"

rm -rf "$WORK"; mkdir -p "$WORK"
KM_LOG="$WORK/azos-bench-minimal.log"
KP_LOG="$WORK/azos-product.log"
# Printed once by `task_create_affinity` (crates/core/sched/src/scheduler.rs) when it
# parks the first task of a `bench-minimal` boot. Matched as a fixed string.
BENCH_MINIMAL_BANNER='[BENCH] bench-minimal: only idle+autorun run; all other tasks parked'
L_LOG="$WORK/linux.log"
S_LOG="$WORK/linux-seccomp.log"

die() { echo "vsbench: $*" >&2; exit 1; }

# ── Assertion 3's justification table: AzOS lanes with no Linux object ────
#
# `<lane label>\t<one-line reason>`, the label exactly as `lane_values`
# extracts it (padding before ` =` stripped, inner spaces kept). A row is a
# claim that Linux has nothing to measure for that lane; the verdict fails a
# row whose lane Linux reports after all, and a row whose lane the gate column
# did not measure (see the header, assertion 3). `printf` rather than a
# heredoc, so the separator is a real tab without a literal one in the source.
justified_azos_only() {
    printf '%s\t%s\n' \
        'sensor-read-call' 'Linux has no sensor syscall: nothing reads a typed sensor through the kernel' \
        'sensor-read-vdso' "Linux's vDSO publishes no sensor data: there is no page to read a sensor from" \
        'sensor-read-ts' 'Linux has no sensor syscall: nothing reads a stamped sensor sample through the kernel' \
        'taskinfo [vdso]' "Linux's vDSO publishes no per-task counters; the call path is 'taskinfo [call]' (getrusage)"
}

# Has this side reached its LAST lane? Used both to stop waiting and, at the
# end, as the verdict — see the long note at the verdict for why a marker line
# is not usable here.
# Either the lane's number OR its refusal counts as "the run got to the end".
#
# The lane can legitimately decline to print a number — it refuses one at or
# below the unloaded yield, because the competitors were not competing. That
# happens about 1 boot in 12 (measured), and without this second pattern a
# refusal would be reported as "the side did not reach its last lane": a
# healthy run, failed for saying something honest. The guard and this check
# were written on the same day and the coupling is easy to miss, which is why
# it is spelled out here.
completion_lane() { # completion_lane <log> <side>
    # A filtered run without `switch` has no last lane: its end is `done`.
    if [ -n "$VSBENCH_LANES" ] && ! printf ',%s,' "$VSBENCH_LANES" | grep -q ',switch,'; then
        tr -d '\r' <"$1" 2>/dev/null | grep -qF "[VSBENCH] side=$2 done"
        return
    fi
    # The lane's LAST line (wave 15): `ctxsw-loaded` or its refusal follows
    # `switch-loaded =`, so stopping on the earlier line could cut it off.
    tr -d '\r' <"$1" 2>/dev/null \
        | grep -qE "\[VSBENCH\] $2 ctxsw-loaded =|\[VSBENCH\] ctxsw-loaded: |\[VSBENCH\] switch-loaded: REFUSED"
}

# ── AzOS side ───────────────────────────────────────────────────────────
# **BUILD THE KERNEL HERE.** This script used to boot whatever binary happened
# to be sitting in `target/`, while building the disk image and the whole Linux
# side itself — so the one artefact it did not produce was the one under test.
#
# It bit on 2026-09-11: a `--features vf2` kernel left over from an unrelated
# build was booted on `-machine virt` and died in Phase 6 with a Store/AMO
# access fault at `0x1602002f`, a JH7110 MMIO address. That reads exactly like
# a kernel regression, and it was a stale artefact. A comparison tool that does
# not own its own inputs compares something nobody chose.
#
# Two kernels, two target directories: neither build overwrites the other, and
# neither writes the repository's default `target/.../release/kernel`.
KM_KERNEL="$BENCH_TARGET/azos-bench-minimal/riscv64imac-unknown-none-elf/release/kernel"
KP_KERNEL="$BENCH_TARGET/azos-product/riscv64imac-unknown-none-elf/release/kernel"

# The kernel embeds the SHA-256 of every shipped ELF (`build/image_hashes.rs`) and
# REFUSES to run one it does not recognise: "matches no seccomp image profile".
# That table is generated by `make`, not by cargo, so a kernel built here after
# `userspace/bench/vsbench` changed carried the OLD hash and never started the
# benchmark. The symptom is "did not reach its last lane" on both kernels and
# nothing about a hash, which reads like a kernel regression (2026-09-18: a server
# loop change, twice; earlier, N_PROC). Regenerate it first, like the gate does.
( cd "$REPO_ROOT" && make build/image_hashes.rs >/dev/null 2>&1 ) \
    || die "could not regenerate build/image_hashes.rs"
# VSBENCH_AZOS_EXTRA_FEATURES: extra kernel features for the gate kernel only,
# for a diagnostic run (e.g. `spawn-census`, whose `[SPAWN-CENSUS]` lines land in
# its boot log). Empty by default: the numbers then are the gate kernel's.
KM_FEATURES="qemu,bench-minimal${VSBENCH_AZOS_EXTRA_FEATURES:+,$VSBENCH_AZOS_EXTRA_FEATURES}"
# Both AzOS kernels are release builds (owner, round 65): the caller's
# configuration (`$KCONFIG_CONFIG`, the gate's primary column; else
# config/defconfigs/qemu.config) with the kernel log level set to
# VSBENCH_LOG_LEVEL, warn by default, so the numbers are those of a kernel
# that prints only errors and refusals, not of the gate's debug console. A
# diagnostic run that reads info lines from the boot log (e.g.
# VSBENCH_AZOS_EXTRA_FEATURES=spawn-census) sets VSBENCH_LOG_LEVEL=debug.
VSBENCH_LOG_LEVEL="${VSBENCH_LOG_LEVEL:-warn}"
case "$VSBENCH_LOG_LEVEL" in
    err|warn|info|debug) ;;
    *) die "VSBENCH_LOG_LEVEL=$VSBENCH_LOG_LEVEL: want err, warn, info or debug" ;;
esac
AZ_LEVEL="CONFIG_LOG_LEVEL_$(printf '%s' "$VSBENCH_LOG_LEVEL" | tr '[:lower:]' '[:upper:]')=y"
AZ_CONFIG="$BENCH_TARGET/azos.config"
mkdir -p "$BENCH_TARGET"
{ grep -v 'LOG_LEVEL' "${KCONFIG_CONFIG:-$REPO_ROOT/config/defconfigs/qemu.config}" \
    && echo "$AZ_LEVEL"; } >"$AZ_CONFIG.new" \
    && ( cd "$REPO_ROOT" && KCONFIG_CONFIG="$AZ_CONFIG.new" python3 -m olddefconfig >/dev/null 2>&1 ) \
    && grep -q "^$AZ_LEVEL\$" "$AZ_CONFIG.new" \
    || die "could not derive the AzOS kernel configuration ($AZ_CONFIG.new)"
# Replaced only when it changed: `azos_limits` rebuilds on the file's mtime.
if cmp -s "$AZ_CONFIG.new" "$AZ_CONFIG"; then rm -f "$AZ_CONFIG.new"; else mv "$AZ_CONFIG.new" "$AZ_CONFIG"; fi
( cd "$REPO_ROOT" && KCONFIG_CONFIG="$AZ_CONFIG" CARGO_TARGET_DIR="$BENCH_TARGET/azos-bench-minimal" \
    $CARGO build --release --features "$KM_FEATURES" >/dev/null 2>&1 ) \
    || die "could not build the AzOS kernel (--features $KM_FEATURES)"
( cd "$REPO_ROOT" && KCONFIG_CONFIG="$AZ_CONFIG" CARGO_TARGET_DIR="$BENCH_TARGET/azos-product" \
    $CARGO build --release --features qemu >/dev/null 2>&1 ) \
    || die "could not build the AzOS kernel (--features qemu)"
[ -f "$KM_KERNEL" ] || die "no kernel at $KM_KERNEL"
[ -f "$KP_KERNEL" ] || die "no kernel at $KP_KERNEL"

# `disk-vsbench.img` autoruns VSBENCH.ELF; the Makefile rule owns that.
( cd "$REPO_ROOT" && make build/disk-vsbench.img >/dev/null 2>&1 ) \
    || die "could not build build/disk-vsbench.img"
[ -f "$REPO_ROOT/build/disk-vsbench.img" ] || die "no build/disk-vsbench.img"

# One AzOS boot, with its own copy of the disk: QEMU locks the file, and the
# guest writes to the FAT32, so a second boot of one copy would start from what
# the first left behind.
# Stop one QEMU this script started. Under `-icount` QEMU can ignore SIGTERM
# (one canary boot waited 10 minutes in `wait`), so a survivor gets SIGKILL.
stop_qemu() { # stop_qemu <pid>
    kill "$1" 2>/dev/null
    sleep 2
    kill -0 "$1" 2>/dev/null && kill -9 "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}

boot_azos() { # boot_azos <kernel> <log> <disk copy>
    cp "$REPO_ROOT/build/disk-vsbench.img" "$3"
    if [ -n "$VSBENCH_LANES" ]; then
        printf '%s\n' "$VSBENCH_LANES" >"$3.lanes"
        mcopy -o -i "$3" "$3.lanes" ::VSBLANES.TXT || die "could not add VSBLANES.TXT to $3"
    fi
    "$QEMU" -machine virt -nographic -bios default -smp "$VSBENCH_SMP" $ICOUNT_ARGS ${BOOT_EXTRA:-} \
        -kernel "$1" \
        -global virtio-mmio.force-legacy=false \
        -drive "file=$3,if=none,format=raw,id=hd0" \
        -device virtio-blk-device,drive=hd0 >"$2" 2>&1 &
    local pid=$!
    for _ in $(seq 1 "${BOOT_WAIT:-$WAIT_SECS}"); do
        completion_lane "$2" azos && break
        sleep 1
    done
    stop_qemu "$pid"
}
boot_azos "$KM_KERNEL" "$KM_LOG" "$WORK/k-bench-minimal.img"
boot_azos "$KP_KERNEL" "$KP_LOG" "$WORK/k-product.img"

# ── Linux side ────────────────────────────────────────────────────────────
if [ ! -f "$LINUX_IMAGE" ]; then
    if [ "${CI_SKIP_VSBENCH_LINUX:-0}" = "1" ]; then
        echo "vsbench: SKIPPED the Linux half (CI_SKIP_VSBENCH_LINUX=1); \
AzOS half only" >&2
        L_LOG=""
    else
        die "no riscv64 Linux at $LINUX_IMAGE. Set VSBENCH_LINUX_IMAGE, or \
CI_SKIP_VSBENCH_LINUX=1 to run the AzOS half alone."
    fi
fi

# One Linux boot: its initramfs, its log, extra kernel command-line words.
# Stops at the last lane, or once PID 1 is gone: `Attempted to kill init!` is
# printed after PID 1's last write, so nothing is lost by stopping there, and a
# run that died early does not sit out the whole `WAIT_SECS`.
boot_linux() { # boot_linux <initramfs> <log> [extra cmdline]
    "$QEMU" -machine virt -nographic -bios default -smp "$VSBENCH_SMP" $ICOUNT_ARGS ${BOOT_EXTRA:-} \
        -kernel "$LINUX_IMAGE" -initrd "$1" \
        -append "rdinit=/init console=ttyS0${3:+ $3}${VSBENCH_LANES:+ VSBENCH_LANES=$VSBENCH_LANES}" >"$2" 2>&1 &
    local pid=$!
    for _ in $(seq 1 "${BOOT_WAIT:-$WAIT_SECS}"); do
        completion_lane "$2" linux && break
        grep -q "Attempted to kill init" "$2" 2>/dev/null && break
        sleep 1
    done
    stop_qemu "$pid"
}

# An UNCOMPRESSED newc initramfs of one directory. Uncompressed on purpose: the
# reference kernel has no gzip initramfs support, and a `.cpio.gz` unpacks into
# nothing and then falls through to mounting a root device — which looks like
# the benchmark producing no output.
pack_initramfs() { # pack_initramfs <dir> <out.cpio>
    ( cd "$1" && find . | cpio -o -H newc ) >"$2" 2>/dev/null
}

L_ELF="$BENCH_TARGET/vsbench-linux/riscv64imac-unknown-none-elf/release/vsbench"
S_RAN=0
S_BUILD_FAILED=0

if [ -n "$L_LOG" ]; then
    # The linker script and target features are the Linux side's; `--no-default-features` is what selects the
    # `linux` ABI, and `main.rs` refuses to build with both or neither.
    ( cd "$REPO_ROOT/userspace/bench/vsbench" \
      && CARGO_TARGET_DIR="$BENCH_TARGET/vsbench-linux" \
         RUSTFLAGS="-C link-arg=-Tlinux.ld $LINUX_RUSTFLAGS" \
         $CARGO +nightly build --release --no-default-features --features "linux${VSBENCH_BENCH_FEATURES:+,$VSBENCH_BENCH_FEATURES}" \
      ) >/dev/null 2>&1 || die "could not build the Linux-side vsbench ELF"

    # The ELF alone, as /init: PID 1, and when it returns Linux panics by design.
    mkdir -p "$WORK/root"
    cp "$L_ELF" "$WORK/root/init"
    chmod +x "$WORK/root/init"
    pack_initramfs "$WORK/root" "$WORK/initramfs.cpio" || die "could not build the initramfs"
    boot_linux "$WORK/initramfs.cpio" "$L_LOG"
fi

# ── Linux + seccomp side ──────────────────────────────────────────────────
# Same ELF, same kernel, same QEMU line. `/init` is the launcher and the ELF is
# `/vsbench`; see the header.
if [ -n "$L_LOG" ] && [ "$VSBENCH_SECCOMP" = "1" ]; then
    S_ELF="$BENCH_TARGET/seccomp-launch/riscv64imac-unknown-none-elf/release/linux_seccomp_launch"
    # `-T` is relative to the launcher crate: RUSTFLAGS is split on spaces and
    # the checkout path may contain some. Target and build-std are given here,
    # not in a config file; tools/linux_seccomp_launch/Cargo.toml says why.
    if ( cd "$REPO_ROOT/tools/linux_seccomp_launch" \
         && CARGO_TARGET_DIR="$BENCH_TARGET/seccomp-launch" \
            RUSTFLAGS="-C link-arg=-T../../userspace/bench/vsbench/linux.ld $LINUX_RUSTFLAGS" \
            $CARGO +nightly build --release --target riscv64imac-unknown-none-elf \
                -Z build-std=core -Z build-std-features=compiler-builtins-mem \
       ) >"$WORK/seccomp-launch-build.log" 2>&1; then
        mkdir -p "$WORK/root-seccomp"
        cp "$S_ELF" "$WORK/root-seccomp/init"
        cp "$L_ELF" "$WORK/root-seccomp/vsbench"
        chmod +x "$WORK/root-seccomp/init" "$WORK/root-seccomp/vsbench"
        pack_initramfs "$WORK/root-seccomp" "$WORK/initramfs-seccomp.cpio" \
            || die "could not build the Linux+seccomp initramfs"
        if [ "$VSBENCH_SECCOMP_CANARY" = "1" ]; then
            boot_linux "$WORK/initramfs-seccomp.cpio" "$S_LOG" "VSBENCH_SECCOMP_CANARY=1"
        else
            boot_linux "$WORK/initramfs-seccomp.cpio" "$S_LOG"
        fi
        S_RAN=1
    else
        S_BUILD_FAILED=1
    fi
fi

# ── The ring lanes' deterministic pass (see VSBENCH_RING_DET) ────────────
KD_LOG="$WORK/azos-bench-minimal-ringdet.log"
LD_LOG="$WORK/linux-ringdet.log"
RING_DET_RAN=0
if [ "$VSBENCH_RING_DET" = "1" ] && [ "$VSBENCH_ICOUNT" != "1" ]; then
    BOOT_EXTRA="$RING_DET_ARGS" BOOT_WAIT="${WAIT_SECS_RING_DET:-$((WAIT_SECS * 3))}" \
        boot_azos "$KM_KERNEL" "$KD_LOG" "$WORK/k-bench-minimal-ringdet.img"
    if [ -n "$L_LOG" ]; then
        BOOT_EXTRA="$RING_DET_ARGS" BOOT_WAIT="${WAIT_SECS_RING_DET:-$((WAIT_SECS * 3))}" \
            boot_linux "$WORK/initramfs.cpio" "$LD_LOG"
    fi
    RING_DET_RAN=1
fi

# ── Verdict ───────────────────────────────────────────────────────────────
rc=0

# COMPLETION IS THE LAST LANE, NOT A MARKER.
#
# `side=<x> done` is printed, but a correct run can mangle it: kernel output
# interleaves with the benchmark's on the same serial console. Observed
# 2026-09-07 on the Linux side, where the final line came out as
#
#   [VSBENCH] side=[    1.007980] Kernlinux del panic - not soneyncing: ...
#
# — `side=linux done` interleaved with `Kernel panic - not syncing: Attempted
# to kill init!`. That panic is EXPECTED, not a failure: this is a single-file
# initramfs run as `rdinit=/init`, so when the benchmark returns, PID 1 exits
# and Linux panics by design. The run had completed.
#
# So completion is asserted as "the last lane is present". `switch-loaded` is
# the final measurement both sides emit; if either died partway it is missing.
# That is a property of the output rather than of one fragile line, and it is
# the third time interleaving has broken this script — the other two were an
# anchored `^` pattern and a literal lookup across padded columns.
completion_lane "$KM_LOG" azos || { echo "vsbench: the azos-min (gate) side did not reach its last lane ($KM_LOG)" >&2; rc=1; }
if grep -q "FAIL rc=" "$KM_LOG"; then
    echo "vsbench: a azos-min (gate) lane failed:" >&2
    grep "FAIL rc=" "$KM_LOG" >&2
    rc=1
fi

# REFUSE the gate column unless the kernel that booted parked its daemons. See
# "Two AzOS columns" in the header for why the log is what is read.
KM_OK=1
if ! tr -d '\r' <"$KM_LOG" 2>/dev/null | grep -qF "$BENCH_MINIMAL_BANNER"; then
    echo "vsbench: REFUSED the azos-min (gate) column: its log lacks the banner" >&2
    echo "         '$BENCH_MINIMAL_BANNER'" >&2
    echo "         so the kernel that booted did not park its daemons ($KM_LOG)" >&2
    KM_OK=0
    rc=1
fi
if tr -d '\r' <"$KP_LOG" 2>/dev/null | grep -qF "$BENCH_MINIMAL_BANNER"; then
    echo "vsbench: the azos-product column booted a bench-minimal kernel ($KP_LOG)" >&2
    rc=1
fi

# The product column: printed, not counted.
completion_lane "$KP_LOG" azos \
    || echo "vsbench: (not counted) the azos-product side did not reach its last lane ($KP_LOG)" >&2
if grep -q "FAIL rc=" "$KP_LOG"; then
    echo "vsbench: (not counted) a azos-product lane failed:" >&2
    grep "FAIL rc=" "$KP_LOG" >&2
fi

# Lane names: only the `<lane> = <n> ns/op` lines. The other `[VSBENCH]` lines
# are tails, counts and prose, which carry no lane to compare.
# Name AND value in ONE pass, into `<lane>\t<ns>` lines.
#
# The first version extracted names and then looked each value up with a
# second, literal grep — and the report padded lane names to a column, so
# `sched-yield   =` has three spaces where `syscall-floor =` has one. Five of
# fourteen lanes silently printed `-` on BOTH sides while the check PASSED:
# the exact "compared two empty sets and called it parity" failure this script
# was written against, reproduced inside it.
#
# Not anchored with `^`, and `\r` stripped first. Both observed, not assumed:
# the QEMU serial console emits CRLF, and kernel output interleaves with the
# benchmark's, so a line can read `[VSBENCH] side=[ML] Input: ...` with the
# marker mid-line. An anchored pattern matched nothing at all.
lane_values() { # lane_values <log> <side>  ->  "<lane>\t<ns>"
    tr -d '\r' <"$1" 2>/dev/null \
        | grep "\[VSBENCH\] $2 " \
        | grep " ns/op" \
        | sed -E "s/.*\[VSBENCH\] $2 +//; s/ +=/=/; s/= *([0-9]+) ns.*/\t\1/" \
        | sort -u
}

# The Linux + seccomp column's own verdict: returns 0 when it is green, and
# prints what it found. Whether a finding changes the exit status is the
# caller's decision (`VSBENCH_SECCOMP_STRICT`). Needs `km.lanes`, `l.lanes` and
# `LANES_NOT_COMPARABLE`; writes `s.tsv`, which the table reads.
seccomp_verdict() {
    local bad=0 code gone
    lane_values "$S_LOG" linux >"$WORK/s.tsv.all"
    grep -vE "^($LANES_NOT_COMPARABLE)\b" "$WORK/s.tsv.all" >"$WORK/s.tsv"
    cut -f1 "$WORK/s.tsv" | sort -u >"$WORK/s.lanes"
    # Printed for the reader, never matched: see the header.
    code="$(tr -d '\r' <"$S_LOG" | grep -oE 'exitcode=0x[0-9a-f]{8}' | head -1)"
    code="${code:-no exitcode line}"

    if grep -q "launcher FAIL" "$S_LOG"; then
        echo "vsbench: the seccomp launcher stopped before vsbench ran:" >&2
        tr -d '\r' <"$S_LOG" | grep "launcher FAIL" | sed 's/^/           /' >&2
        return 1
    fi

    if [ "$VSBENCH_SECCOMP_CANARY" = "1" ]; then
        # Green only if the launcher reached the denied call and died there:
        # the canary line, the kernel's report of PID 1 gone, and nothing of
        # vsbench. `launcher FAIL` above is what a returning getppid prints.
        if grep -q "canary: calling getppid" "$S_LOG" \
           && grep -q "Attempted to kill init" "$S_LOG" \
           && ! grep -q "\[VSBENCH\] linux " "$S_LOG"; then
            echo "vsbench: seccomp canary: the launcher died on getppid ($code); a denied call kills" >&2
            return 0
        fi
        echo "vsbench: seccomp canary: the launcher did NOT die on getppid ($S_LOG)" >&2
        return 1
    fi

    if grep -q "type=1326" "$S_LOG"; then
        echo "vsbench: seccomp audit records in the Linux+seccomp log (syscall= names the call):" >&2
        tr -d '\r' <"$S_LOG" | grep "type=1326" | sed 's/^/           /' >&2
        bad=1
    fi
    if ! grep -q "filter installed" "$S_LOG"; then
        echo "vsbench: the seccomp launcher never reported its filter installed ($S_LOG)" >&2
        return 1
    fi
    if ! grep -q "\[VSBENCH\] linux " "$S_LOG"; then
        echo "vsbench: filter installed, then no vsbench output ($code): killed at or right \
after execve, before vsbench's first write ($S_LOG)" >&2
        return 1
    fi
    completion_lane "$S_LOG" linux || {
        echo "vsbench: the Linux+seccomp side did not reach its last lane ($code) ($S_LOG)" >&2
        bad=1
    }
    if grep -q "FAIL rc=" "$S_LOG"; then
        echo "vsbench: a Linux+seccomp lane failed (a forked peer killed by the filter reads this way):" >&2
        grep "FAIL rc=" "$S_LOG" >&2
        bad=1
    fi
    gone="$(comm -23 "$WORK/l.lanes" "$WORK/s.lanes")"
    if [ -n "$gone" ]; then
        echo "vsbench: lanes the unfiltered Linux column measured and the Linux+seccomp column" >&2
        echo "         did not; same binary and kernel, so this points at the filter" >&2
        echo "         (tools/linux_seccomp_launch/src/allow.rs):" >&2
        echo "$gone" | sed 's/^/           /' >&2
        bad=1
    fi
    # Less the justified lanes: a lane with no Linux object has none under a
    # filter either, and assertion 3 has already judged the table.
    gone="$(comm -23 "$WORK/km.lanes" "$WORK/s.lanes" | comm -23 - "$WORK/justified.lanes")"
    if [ -n "$gone" ]; then
        echo "vsbench: azos-min (gate) lanes with no Linux+seccomp counterpart:" >&2
        echo "$gone" | sed 's/^/           /' >&2
        bad=1
    fi
    return $bad
}

if [ -n "$L_LOG" ]; then
    completion_lane "$L_LOG" linux || { echo "vsbench: the Linux side did not reach its last lane ($L_LOG)" >&2; rc=1; }
    if grep -q "FAIL rc=" "$L_LOG"; then
        echo "vsbench: a Linux lane failed:" >&2
        grep "FAIL rc=" "$L_LOG" >&2
        rc=1
    fi

    lane_values "$KM_LOG" azos >"$WORK/km.tsv.all"
    lane_values "$KP_LOG" azos >"$WORK/kp.tsv.all"
    lane_values "$L_LOG" linux  >"$WORK/l.tsv.all"

    # ── Lanes that are NOT comparable, and why each one is listed ─────────
    #
    # `switch-loaded`: measured 2026-09-11 (`-smp 4`) with both kernels' own
    # switch counters, AzOS switched on 500 of 500 yields and Linux on 0 of
    # 500. At `-smp 1` (wave 15) Linux switches, but runs ~1 competitor yield
    # per op where AzOS runs 4: one op is not the same work on the two
    # kernels. `ctxsw-loaded` (same window, per context switch) is the lane
    # that compares; this one stays in each side's own output, not in a
    # column headed "azos / linux".
    #
    # `sleep-until0` and `ioring-tmr xN` (2026-09-27): AzOS completes a
    # deadline that has already passed inside the call; Linux arms an hrtimer
    # that has already expired and completes it from the timer interrupt, so
    # its side is interrupt-to-wake latency (17-330 us per op, not monotonic in
    # N, ordering flipping between runs). Same label, different event.
    #
    # A list, not a deletion, and not a silent filter: an excluded lane that
    # leaves no trace is how "we compared these" quietly becomes untrue.
    # An extended regex over lane names (some contain spaces).
    LANES_NOT_COMPARABLE='switch-loaded|sleep-until0|ioring-tmr'
    grep -vE "^($LANES_NOT_COMPARABLE)\b" "$WORK/km.tsv.all" >"$WORK/km.tsv"
    grep -vE "^($LANES_NOT_COMPARABLE)\b" "$WORK/kp.tsv.all" >"$WORK/kp.tsv"
    grep -vE "^($LANES_NOT_COMPARABLE)\b" "$WORK/l.tsv.all" >"$WORK/l.tsv"
    echo "vsbench: excluded from the comparison as not measuring the same event:" >&2
    cat "$WORK/km.tsv.all" "$WORK/l.tsv.all" | cut -f1 | grep -E "^($LANES_NOT_COMPARABLE)\b" \
        | sort -u | while IFS= read -r l; do
        printf '           %-16s azos-min %-10s azos-product %-10s linux %s\n' "$l" \
            "$(awk -F'\t' -v k="$l" '$1 == k { print $2; exit }' "$WORK/km.tsv.all")" \
            "$(awk -F'\t' -v k="$l" '$1 == k { print $2; exit }' "$WORK/kp.tsv.all")" \
            "$(awk -F'\t' -v k="$l" '$1 == k { print $2; exit }' "$WORK/l.tsv.all")" >&2
    done
    cut -f1 "$WORK/km.tsv" | sort -u >"$WORK/km.lanes"
    cut -f1 "$WORK/kp.tsv" | sort -u >"$WORK/kp.lanes"
    cut -f1 "$WORK/l.tsv" | sort -u >"$WORK/l.lanes"

    # A lane that parsed to no number is a parsing failure, not a measurement.
    # Asserted because the alternative is a table of dashes that passes.
    if [ ! -s "$WORK/km.lanes" ]; then
        echo "vsbench: parsed NO lanes from the azos-min (gate) log — the report \
format moved and this script did not ($KM_LOG)" >&2
        rc=1
    fi
    if [ ! -s "$WORK/kp.lanes" ]; then
        echo "vsbench: (not counted) parsed NO lanes from the azos-product log ($KP_LOG)" >&2
    fi

    # Every AzOS lane must have a Linux counterpart. The reverse is allowed:
    # Linux measures `getcpu`, which this kernel offers by neither path and
    # reports as such in its own output.
    #
    # A lane with no counterpart passes only through a row of
    # `justified_azos_only`, and every row must still be needed (header,
    # assertion 3, a-c). Lane names hold spaces and `[`, so every lookup is a
    # whole-field `awk` match or a `comm` of sorted files, never a regex.
    justified_azos_only >"$WORK/justified.tsv"
    cut -f1 "$WORK/justified.tsv" | sort -u >"$WORK/justified.lanes"
    reason() { # reason <lane>
        awk -F '\t' -v l="$1" '$1 == l { print $2; exit }' "$WORK/justified.tsv"
    }
    comm -23 "$WORK/km.lanes" "$WORK/l.lanes" >"$WORK/km.missing"
    missing="$(comm -23 "$WORK/km.missing" "$WORK/justified.lanes")"
    if [ -n "$missing" ]; then
        echo "vsbench: azos-min (gate) lanes with no Linux counterpart — step 9 requires" >&2
        echo "         parity or a justification per measurement, and these have neither:" >&2
        echo "$missing" | sed 's/^/           /' >&2
        rc=1
    fi
    justified="$(comm -12 "$WORK/km.missing" "$WORK/justified.lanes")"
    if [ -n "$justified" ]; then
        echo "vsbench: azos-min (gate) lanes with no Linux counterpart, JUSTIFIED (no Linux object to measure):" >&2
        echo "$justified" | while IFS= read -r l; do
            printf '           %-18s %s\n' "$l" "$(reason "$l")" >&2
        done
    fi
    stale="$(comm -12 "$WORK/justified.lanes" "$WORK/l.lanes")"
    if [ -n "$stale" ]; then
        echo "vsbench: STALE justification: Linux reports these lanes, so 'no Linux object' is" >&2
        echo "         false — delete the row from justified_azos_only:" >&2
        echo "$stale" | while IFS= read -r l; do
            printf '           %-18s linux %s ns/op  (row says: %s)\n' "$l" \
                "$(awk -F '\t' -v l="$l" '$1 == l { print $2; exit }' "$WORK/l.tsv")" \
                "$(reason "$l")" >&2
        done
        rc=1
    fi
    stale="$(comm -23 "$WORK/justified.lanes" "$WORK/km.lanes")"
    if [ -n "$stale" ]; then
        echo "vsbench: STALE justification: the azos-min (gate) column did not measure these" >&2
        echo "         lanes, so their rows justify nothing (renamed, removed, or failed):" >&2
        echo "$stale" | sed 's/^/           /' >&2
        rc=1
    fi
    missing="$(comm -23 "$WORK/kp.lanes" "$WORK/l.lanes" | comm -23 - "$WORK/justified.lanes")"
    if [ -n "$missing" ]; then
        echo "vsbench: (not counted) azos-product lanes with no Linux counterpart:" >&2
        echo "$missing" | sed 's/^/           /' >&2
    fi

    # ── Linux + seccomp verdict ──────────────────────────────────────────
    S_SHOW=0
    if [ "$VSBENCH_SECCOMP" = "1" ]; then
        s_bad=0
        if [ "$S_BUILD_FAILED" = "1" ]; then
            echo "vsbench: could not build tools/linux_seccomp_launch; no Linux+seccomp \
column ($WORK/seccomp-launch-build.log)" >&2
            s_bad=1
        elif [ "$S_RAN" = "1" ]; then
            seccomp_verdict || s_bad=1
            [ "$VSBENCH_SECCOMP_CANARY" = "1" ] || S_SHOW=1
        fi
        # A AzOS column beside `linux+seccomp` compares two filtered paths
        # only if the kernel installed VSBENCH.ELF's image profile. Read from
        # each log rather than assumed. The line is the autorun loader's in
        # kernel/src/tasks/loader.rs.
        # That line is info: a warn-level kernel (VSBENCH_LOG_LEVEL, the
        # default) does not print it. There the evidence is the loader's
        # contract: an image no profile is bound to is REFUSED, not run, and
        # a profile that could not be installed or runs in audit mode prints
        # a warn line. So VSBENCH.ELF reaching its last lane with none of
        # those lines ran under the profile bound to its bytes.
        for kl in "$KM_LOG" "$KP_LOG"; do
            if tr -d '\r' <"$kl" | grep -qE '\[AUTORUN\] seccomp: [^ ]*VSBENCH\.ELF runs under the VSBENCH\.ELF profile'; then
                echo "vsbench: VSBENCH.ELF ran under its image profile ($kl)" >&2
            elif [ "$VSBENCH_LOG_LEVEL" = warn ] && completion_lane "$kl" azos \
                 && ! tr -d '\r' <"$kl" | grep -qE '\[AUTORUN\] (REFUSED|seccomp: )'; then
                echo "vsbench: VSBENCH.ELF ran to its last lane, no refusal or seccomp \
warning (warn-level kernel): under its image profile ($kl)" >&2
            else
                echo "vsbench: the log does not show VSBENCH.ELF under its image profile \
(expected '[AUTORUN] seccomp: ...VSBENCH.ELF runs under the VSBENCH.ELF profile') ($kl)" >&2
                tr -d '\r' <"$kl" | grep '\[AUTORUN\] REFUSED' | sed 's/^/           /' >&2
                s_bad=1
            fi
        done
        if [ "$s_bad" = "1" ]; then
            if [ "$VSBENCH_SECCOMP_STRICT" = "1" ]; then
                rc=1
            else
                echo "vsbench: the seccomp findings above do not change the exit status \
(VSBENCH_SECCOMP_STRICT=0)" >&2
            fi
        fi
    fi

    # One value per (column, lane). An exact match on the lane field: a
    # substring match would let `yield` pick up `sched-yield`.
    cell() { # cell <tsv> <lane>
        awk -F '\t' -v l="$2" '$1 == l { print $2; exit }' "$WORK/$1" 2>/dev/null
    }
    sort -u "$WORK/km.lanes" "$WORK/kp.lanes" >"$WORK/rows"

    echo ""
    echo "  vsbench, same work on each side (absolutes; the ratios are unstable)."
    echo "  GATE:azos-min (qemu,bench-minimal) against linux is the hardware-gate comparison;"
    echo "  azos-product (qemu, full daemon set) is published for its cost and does not gate."
    printf "    %-16s %16s %16s %14s" "lane" "GATE:azos-min" "azos-product" "linux"
    [ "$S_SHOW" = "1" ] && printf " %14s" "linux+seccomp"
    printf "\n"
    while read -r lane; do
        if [ "$KM_OK" = "1" ]; then m="$(cell km.tsv "$lane")"; else m="refused"; fi
        p="$(cell kp.tsv "$lane")"
        l="$(cell l.tsv "$lane")"
        # A justified lane's empty Linux cell says so; any other empty cell
        # stays `-`, which assertion 3 has already failed.
        none="-"
        [ -n "$(reason "$lane")" ] && none="justified"
        printf "    %-16s %16s %16s %14s" "$lane" "${m:--}" "${p:--}" "${l:-$none}"
        if [ "$S_SHOW" = "1" ]; then
            sv="$(cell s.tsv "$lane")"
            printf " %14s" "${sv:-$none}"
        fi
        printf "\n"
    done <"$WORK/rows"
    echo ""
fi

# ── Ring lanes, deterministic pass: its own assertions and table ─────────
if [ "$RING_DET_RAN" = "1" ]; then
    completion_lane "$KD_LOG" azos || { echo "vsbench: the azos-min ring pass ($RING_DET_ARGS) did not reach its last lane ($KD_LOG)" >&2; rc=1; }
    if grep -q "FAIL rc=" "$KD_LOG"; then
        echo "vsbench: a azos-min lane failed in the ring pass:" >&2
        grep "FAIL rc=" "$KD_LOG" >&2
        rc=1
    fi
    if ! tr -d '\r' <"$KD_LOG" 2>/dev/null | grep -qF "$BENCH_MINIMAL_BANNER"; then
        echo "vsbench: REFUSED the azos-min ring pass: its log lacks the bench-minimal banner ($KD_LOG)" >&2
        rc=1
    fi
    # Set by the comparison block above; without a Linux half it is not,
    # and of its lanes only `ioring-tmr` can match a ring lane.
    LANES_NOT_COMPARABLE="${LANES_NOT_COMPARABLE:-ioring-tmr}"
    lane_values "$KD_LOG" azos | grep -E "$RING_LANES_RE" >"$WORK/kd.tsv.all"
    grep -vE "^($LANES_NOT_COMPARABLE)\b" "$WORK/kd.tsv.all" >"$WORK/kd.tsv"
    cut -f1 "$WORK/kd.tsv" | sort -u >"$WORK/kd.lanes"
    if [ ! -s "$WORK/kd.lanes" ]; then
        echo "vsbench: parsed NO ring lanes from the azos-min ring pass ($KD_LOG)" >&2
        rc=1
    fi
    : >"$WORK/ld.tsv.all"
    if [ -n "$L_LOG" ]; then
        completion_lane "$LD_LOG" linux || { echo "vsbench: the Linux ring pass ($RING_DET_ARGS) did not reach its last lane ($LD_LOG)" >&2; rc=1; }
        if grep -q "FAIL rc=" "$LD_LOG"; then
            echo "vsbench: a Linux lane failed in the ring pass:" >&2
            grep "FAIL rc=" "$LD_LOG" >&2
            rc=1
        fi
        lane_values "$LD_LOG" linux | grep -E "$RING_LANES_RE" >"$WORK/ld.tsv.all"
        grep -vE "^($LANES_NOT_COMPARABLE)\b" "$WORK/ld.tsv.all" >"$WORK/ld.tsv"
        cut -f1 "$WORK/ld.tsv" | sort -u >"$WORK/ld.lanes"
        # Assertion 3 for this pass: no ring lane is on the justified list,
        # so every AzOS ring lane needs a Linux number here.
        missing="$(comm -23 "$WORK/kd.lanes" "$WORK/ld.lanes")"
        if [ -n "$missing" ]; then
            echo "vsbench: azos-min ring lanes with no Linux counterpart in the ring pass:" >&2
            echo "$missing" | sed 's/^/           /' >&2
            rc=1
        fi
    fi
    rcell() { # rcell <tsv> <lane>
        awk -F '\t' -v l="$2" '$1 == l { print $2; exit }' "$WORK/$1" 2>/dev/null
    }
    echo "  vsbench ring lanes, second boot under $RING_DET_ARGS, -smp $VSBENCH_SMP:"
    echo "  instructions per op (reproducible), not ns; the wall-clock ring rows above are host-bound."
    printf "    %-16s %16s %14s\n" "lane" "GATE:azos-min" "linux"
    cut -f1 "$WORK/kd.tsv.all" "$WORK/ld.tsv.all" | sort -u | while IFS= read -r lane; do
        [ -n "$lane" ] || continue
        note=""
        printf '%s\n' "$lane" | grep -qE "^($LANES_NOT_COMPARABLE)\b" && note="  (not compared)"
        printf "    %-16s %16s %14s%s\n" "$lane" "$(rcell kd.tsv.all "$lane")" "$(rcell ld.tsv.all "$lane")" "$note"
    done
    echo ""
fi

exit $rc
