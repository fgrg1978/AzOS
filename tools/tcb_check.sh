#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Certified-partition check (renamed 2026-09-26, audit item Q2.1).
#
# RENAMED CLAIM (Q2.1): this script does NOT measure the TCB. The TCB is the
# linked kernel image — every crate in it runs in S-mode and can write the
# e-stop latch, scaffolding included. What this script measures is the
# CERTIFIED PARTITION: which crates the project is willing to call "core"
# for review/audit purposes, and whether that partition's own internal rule
# (core may not depend on scaffolding, and — as of the PROFILE list below —
# core may not depend on profile) holds against the actual Cargo.toml graph.
# Calling that partition "the TCB" claimed a safety property (a FAT32 or TCP
# bug is outside the TCB) that the crate graph does not deliver: every crate
# still links into one S-mode image. The second metric this script now
# prints (S-mode lines by crate) is the honest number for that: the goal it
# names — move it, starting with one parser (Q2.2, not this script's job) —
# is a real placement change, not a bigger CORE_CRATES list.
#
# The owner rejected two easier designs and picked a harder one:
#
#   * A feature flag ("safety" vs "full") was rejected because a negative
#     feature rots silently — nothing forces every future crate to remember
#     to gate itself out, and the day it is forgotten the flag still builds,
#     green, carrying the thing it was supposed to exclude.
#   * Measuring the whole linked image was rejected because a single number
#     that goes up or down with unrelated changes helps nobody decide
#     anything.
#
# Instead: core and scaffolding are separated **by crate**, and the boundary
# is a property of the `Cargo.toml` dependency graph — a core crate may not
# depend on a scaffolding crate. That is checkable without running anything,
# it cannot be forgotten (a new crate that isn't listed on either side is
# flagged, not silently allowed), and it fails on the exact edge that broke
# it, not on a vibe.
#
# The rule for which side a crate is on (owner's, 2026-09-05): core is
# everything that can move or stop a motor, PLUS all of `crates/net/net` — the
# e-stop arrives over TCP, so the network stack that carries it is core too.
# Scaffolding is everything else: FAT32, the shell, ML/GGUF, camera, DFU,
# OTA, TFTP, USB MSC, UEFI boot, the HDMI framebuffer, the synthetic
# benchmarks, and the tracing/profiling ring buffer. The lists below carry the
# one-line justification of every crate on both sides, and of the crates
# that were genuinely ambiguous.
#
# PROFILE (added 2026-09-26, Fable audit Q2.3, owner default): a third list,
# for the robot payload — sensors, flight math, and the behavior arbiter that
# reads them. Profile may depend on core; core may NOT depend on profile.
# `tcb_check.sh` used to list these nine directly under CORE_CRATES ("core is
# everything that can move or stop a motor" reads them as core), but the
# audit's own point stands: they are the ROBOT profile, not a property every
# hybrid build needs, and RFC-0040's pivot (2026-09-22) already treats "the
# robot" as a profile in prose. `degrade-policy` (motor-actuation policy) is
# added to this list beyond Q2.3's own shorthand of nine names, for the
# reason its OWN Cargo.toml already gives: "degrade taxonomy + speed-ceiling
# mapping live in this dep-free leaf so that motor-actuation policy does not
# pollute the TCB" (crates/core/ipc/Cargo.toml) — that is this exact rule, stated
# before this list existed to enforce it.
#
# Moving these ten out of CORE_CRATES does not by itself move any code — it
# turns two known dependency edges into CHECKED violations instead of
# invisible ones (see the baseline below), which is the point: the crate
# graph now says what prose already claimed.
#
# `kernel` itself is deliberately checked against NEITHER list. It is the
# composition root: on today's tree it links core, profile, and scaffolding
# together into one binary by design (that is what step 3's future "safety
# build" feature-gating is for), so holding it to the same rule as a library
# crate would fail trivially on every crate in the workspace and say nothing.
#
# Usage: ./tools/tcb_check.sh
#        (also wired into ./tools/ci_check.sh)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATES_DIR="$REPO_ROOT/crates"
# crate_dir <name>: the crate lives in one of the restructured groups (wave 11).
# A bare name is searched group by group; a name that is ambiguous across
# groups (`net`: crates/net/net is the stack, crates/drivers/net the NIC class)
# is listed group-qualified, `drivers/net`, and resolves under crates/ or
# domains/ directly (w14).
crate_dir() {
    local g
    case "$1" in
        */*)
            for g in crates domains; do
                if [ -f "$REPO_ROOT/$g/$1/Cargo.toml" ]; then printf '%s' "$REPO_ROOT/$g/$1"; return 0; fi
            done
            printf '%s' "$CRATES_DIR/$1"; return 0 ;;
    esac
    for g in crates/core crates/fs crates/net crates/drivers domains/robot; do
        if [ -f "$REPO_ROOT/$g/$1/Cargo.toml" ]; then printf '%s' "$REPO_ROOT/$g/$1"; return 0; fi
    done
    printf '%s' "$CRATES_DIR/$1"
}

# ── The partition (single source of truth) ──────────────────────────────────
#
# Directory names under crates/ and domains/ (group-qualified where a name is
# in two groups). The Cargo *package* name is read from each Cargo.toml
# (`pkg_name`): the driver class crates (w14) break the old `azos_<dir>`
# rule — crates/drivers/sys is `azos_drv_sys`, domains/robot/drivers is
# `azos_robot_drivers`.

CORE_CRATES="
abi arch arch-api arch-riscv64 arch-aarch64 common sync mm limits
api base irqchip sys gpio bus virtio block drivers/net sensor actuator npu power dmac
driver_server ina219 buzzer spsc pci dma iommu
ipc sched syscall net energy
crypto encrypt-link
actuation channel
config topology pubsub service multi-stream dtb
linux-abi
percpu trace
chaos decision
"
# Wave 11 (DOMAIN): `actuation` (crates/core/actuation) is the authority
# every domain shares — e-stop latch, signed release, flight recorder,
# sys-wdt, the timer-ISR feed — extracted from `safety-core` and `behavior`.
# What stayed in `safety-core` is the robot's part (motor gate and
# envelope wiring, rt-motor, flight control, I-13 rollback), so it moved to
# PROFILE: it links only into a DOMAIN_ROBOT image.
# pci/dma joined CORE 2026-09-26 (RFC-0046 stage 1): the drivers crate (CORE)
# had an optional path dependency on both (its `pci` feature) for the
# virtio-pci modern transport; since w14 that is `virtio` (crates/drivers/virtio)
# on `pci` alone. Putting them in
# SCAFFOLD_CRATES instead — "PCI enumeration/DMA mapping can't move a
# motor" was this task's own first instinct — would have drawn a CORE ->
# SCAFFOLD edge, exactly what this script's rule forbids: the partition is
# by DEPENDENCY DIRECTION, not by capability. `iommu` joined CORE the same
# day, pre-emptively: nothing depends on it yet (its Cargo.toml is wired
# into `kernel`'s optional `iommu` feature but no CORE crate calls into it
# from real code), but it sits at the same
# layer as `pci`/`dma` and will get a real CORE-crate caller (`drivers` or
# `kernel`) the moment gate 1b's fault-record sink is wired, so placing it
# in SCAFFOLD now would just mean moving it again later for the same
# reason. Re-run this script after that wiring lands to confirm the
# decision instead of trusting this comment.

# `energy` joined CORE in wave 12 (RFC-0051 E0-E2): the scheduler's energy seams and
# utilisation tracker (pure, no_std); `sched` (CORE) depends on it.

# `spsc` joined CORE in wave 11 (SHMRING): the single-producer ring the kernel
# publishes sensor streams through (crates/core/ipc stream_ring); libsys re-exports it.

# `linux-abi` joined CORE in wave 12 (RFC-0047): the Linux personality's
# numbers and layouts, a dependency of `sched` (the initial stack's auxv) and
# `syscall` (the translation); by dependency direction it can only be CORE.

# `ina219` joined CORE in wave 11 (DRVPLACE): the INA219 chip logic, a
# dependency of `drivers` (CORE) for its in-kernel placement; by dependency
# direction it can only be CORE.
# `buzzer` joined CORE in wave 12 (DRVPLACE): the buzzer chip logic, the
# same shape and the same dependency edge from `drivers` as `ina219`.

# `percpu` and `trace` joined CORE in wave 15, by dependency direction:
# `percpu` (NRCPUS) holds the per-CPU areas `sched`, `mm` and `trace` reach
# their per-CPU state through; `trace` (block A, TRACE) is the static-key
# tracepoint layer `sched`, `ipc` and `syscall` call on their hot paths, so
# it can no longer sit in SCAFFOLD (that drew three CORE -> SCAFFOLD edges,
# the row's red since c44e9b85). Its own dependencies (abi, spsc, percpu) are
# CORE.

# `chaos` and `decision` joined CORE in wave 15, by dependency direction:
# `sched`, `mm`, `ipc` and `syscall` (and the block driver class) call their
# injection points (Kconfig CHAOS) and decision records (Kconfig
# DECISION_RECORDS) from their own paths, so either one in SCAFFOLD or
# PROFILE draws CORE -> SCAFFOLD/PROFILE edges. Both depend only on `limits`
# (CORE). Off, each compiles to constants: CHAOS's `fire` is false and
# `record` is empty.

PROFILE_CRATES="
behavior flight flight-math nav robot ahrs baro gps imu degrade-policy safety-core drivers
lx-loader
"

# `ktest` joined SCAFFOLD in wave 15 (KTEST): the in-kernel test registry,
# compiled into a kernel only with Kconfig KTEST (a test kernel the gate
# boots); no CORE crate depends on it, only the kernel binary's tests do.
SCAFFOLD_CRATES="
fs shell ml camera dfu ota msc efi display bench cam-ring telemetry tftp
ktest
"

# ── Known violations ────────────────────────────────────────────────────────
#
# When the partition above was drawn (2026-09-05) it did not find a clean
# graph — it exposed one that was never clean. Three edges from a core crate
# to a scaffolding crate existed then. All three are closed, and none of them
# is in the manifests today (re-checked against each Cargo.toml 2026-09-14):
#
#   azos_syscall  -> azos_fs     CLOSED 2026-09-05. The file syscalls
#                        go through the `FileOps` trait in
#                        crates/core/syscall/src/file_ops.rs; the kernel supplies
#                        FAT32 and owns the descriptor table.
#   azos_behavior -> azos_fs     CLOSED 2026-09-05. The flight
#                        recorder (logger.rs) declares a `LogStorage` trait
#                        and the kernel supplies FAT32.
#   azos_net      -> azos_tftp   CLOSED 2026-09-05. The boot-time
#                        TFTP fetch loop moved to crates/net/tftp/src/client.rs
#                        behind a `UdpTransport` trait.
#
# The comments on each list entry keep the reasoning. The check started at the true
# count (3), because a check that is wrong on day one gets ignored on day two,
# and ratcheted down as each edge closed. It is allowed to stay at 0 — never
# to grow.
BASELINE_VIOLATIONS=0

# ── Known core -> profile edges (2026-09-26, new with the PROFILE list) ────
#
# Moving the nine Q2.3 crates plus `degrade-policy` out of CORE_CRATES turns
# these EIGHT existing dependency edges into violations of the new rule
# ("core may not depend on profile"). None of them is fixed here — they
# belong to the crates on the CORE side (`ipc`, `syscall`, `safety-core`),
# which this front does not own — and the audit's own [rec] for Q2.3 names
# the fix as "the same trait-inversion used for FileOps", one wave of seam
# work, not a same-day patch. Started at the true count for the same reason
# BASELINE_VIOLATIONS above was: a check that opens already red gets ignored.
#
#   azos_ipc         -> azos_degrade_policy   (named in Q2.3 itself)
#   azos_syscall     -> azos_robot            (named in Q2.3 itself)
#   azos_syscall     -> azos_gps              (named in Q2.3 itself)
#   azos_syscall     -> azos_imu              (named in Q2.3 itself)
#   azos_safety_core -> azos_behavior         (found implementing this)
#   azos_safety_core -> azos_flight           (found implementing this)
#   azos_safety_core -> azos_robot            (found implementing this)
#   azos_safety_core -> azos_ahrs             (found implementing this)
#
# The `safety-core` four were NOT named in the audit's own shorthand list —
# found by running this check against the full CORE_CRATES list, not just
# the two crates Q2.3 called out. `domains/robot/safety-core/Cargo.toml`'s own
# header comment ("Core crate: it depends on core crates only") is now
# false; this script does not edit that file. Report, do not fix (task
# instruction) — flagging it here so it is not lost between fronts.
#
# Wave 11 (DOMAIN) closed all eight. `ipc` declares the five degrade-level
# numbers itself (the speed mapping stays in `degrade-policy`, cross-checked at
# compile time in `behavior`); `safety-core` is PROFILE now (see CORE_CRATES);
# `syscall`'s three became OPTIONAL dependencies enabled only by its
# `domain-robot` feature (the kernel's Robot domain), with
# `crates/core/syscall/src/no_robot.rs` standing in without it. An optional
# dependency is not counted here: `deps_of` skips `optional = true` lines and
# `optional_deps_of` lists them under "domain-gated edges" below, so they stay
# visible. A NON-optional core -> profile edge is a violation again.
BASELINE_PROFILE_VIOLATIONS=0

pkg_name() { # pkg_name <name> -> the package name its Cargo.toml declares
    # Read, not derived: the driver class crates (w14) are `azos_drv_<class>`
    # in crates/drivers/<class>, so `azos_<dir>` no longer holds everywhere.
    sed -n 's/^name *= *"\(.*\)"/\1/p' "$(crate_dir "$1")/Cargo.toml" | sed -n 1p
}

is_in() { # is_in <needle> <haystack (space-separated)>
    local needle="$1" hay="$2" w
    for w in $hay; do
        [ "$w" = "$needle" ] && return 0
    done
    return 1
}

# Print the azos_* dependency package names listed under [dependencies]
# in a Cargo.toml. Deliberately does not look at [dev-dependencies],
# [build-dependencies] or [features] — a crate forwarding a feature flag to
# another crate's name (e.g. behavior's
# `link-encrypt-enforced = ["azos_encrypt_link/link-encrypt-enforced"]`)
# is not a compile-time dependency edge and must not be counted as one.
#
# Pure bash: no jq, no python, no `rg` (this repo's scripts run under
# `bash -c`, where `rg` does not exist), no cargo metadata (this check must
# work even when the workspace does not currently build).
deps_of() { # deps_of <path/to/Cargo.toml>  (non-optional dependencies only)
    local toml="$1" in_deps=0 line key
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "[dependencies]") in_deps=1; continue ;;
            "["*) in_deps=0 ;;
        esac
        [ "$in_deps" = 1 ] || continue
        case "$line" in
            *"optional = true"*) continue ;;
        esac
        case "$line" in
            azos_*)
                key="${line%%=*}"
                # trim trailing spaces left by "name = value"
                while [ "${key% }" != "$key" ]; do key="${key% }"; done
                printf '%s\n' "$key"
                ;;
        esac
    done < "$toml"
}

# The optional azos_* dependencies of a Cargo.toml (wave 11): linked only
# when a feature names them, reported as domain-gated edges, not counted.
optional_deps_of() { # optional_deps_of <path/to/Cargo.toml>
    local toml="$1" in_deps=0 line key
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "[dependencies]") in_deps=1; continue ;;
            "["*) in_deps=0 ;;
        esac
        [ "$in_deps" = 1 ] || continue
        case "$line" in
            azos_*"optional = true"*)
                key="${line%%=*}"
                while [ "${key% }" != "$key" ]; do key="${key% }"; done
                printf '%s\n' "$key"
                ;;
        esac
    done < "$toml"
}

violations=0
findings=""
gated_findings=""
profile_violations=0
profile_findings=""

for c in $CORE_CRATES; do
    toml="$(crate_dir "$c")/Cargo.toml"
    if [ ! -f "$toml" ]; then
        echo "  FATAL: tcb_check.sh lists core crate '$c' but $toml does not exist."
        echo "         The partition in this script has drifted from the tree — fix"
        echo "         the CORE_CRATES list before trusting anything else it reports."
        exit 1
    fi
    core_pkg="$(pkg_name "$c")"
    for dep in $(optional_deps_of "$toml"); do
        for p in $PROFILE_CRATES; do
            [ "$dep" = "$(pkg_name "$p")" ] && gated_findings="${gated_findings}  ${core_pkg} -> ${dep}\n"
        done
    done
    for dep in $(deps_of "$toml"); do
        for s in $SCAFFOLD_CRATES; do
            scaf_pkg="$(pkg_name "$s")"
            if [ "$dep" = "$scaf_pkg" ]; then
                violations=$((violations + 1))
                findings="${findings}  ${core_pkg} -> ${scaf_pkg}\n"
            fi
        done
        # Q2.3: core may not depend on profile, the same shape of rule as
        # core-may-not-depend-on-scaffolding above, checked separately so a
        # scaffolding regression and a profile regression are never confused
        # in the count (they carry different baselines and different owners).
        for p in $PROFILE_CRATES; do
            prof_pkg="$(pkg_name "$p")"
            if [ "$dep" = "$prof_pkg" ]; then
                profile_violations=$((profile_violations + 1))
                profile_findings="${profile_findings}  ${core_pkg} -> ${prof_pkg}\n"
            fi
        done
    done
done

# Print the "crates/<dir>" workspace members listed in the root Cargo.toml's
# `members = [...]` array, as bare <dir> names. This is the authoritative
# list of what actually gets built into the kernel binary — NOT "every
# directory under crates/", which also holds the excluded host-side tooling
# (flight-sim, azos-config, wcet-macro, auth-envelope-bench, every
# `*-tests` suite) that never compiles for riscv64 and never ships. Deriving
# this from the tree instead of hand-listing it means a crate moved from
# `exclude` to `members` (or the reverse) is picked up automatically, rather
# than needing this script edited in lockstep — exactly the kind of drift
# the unlisted-crate check below exists to catch in the other direction.
workspace_member_dirs() {
    local toml="$REPO_ROOT/Cargo.toml" in_members=0 line rest name
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "members = ["*) in_members=1 ;;
        esac
        if [ "$in_members" = 1 ]; then
            case "$line" in
                *'"crates/'*|*'"domains/'*)
                    rest="${line#*\"}"
                    path="${rest%%\"*}"
                    name="${path##*/}"
                    # The key the lists use: the bare name when it resolves
                    # back to this member, else group-qualified (`drivers/net`).
                    if [ "$(crate_dir "$name")" != "$REPO_ROOT/$path" ]; then
                        name="${path#*/}"
                    fi
                    printf '%s\n' "$name"
                    ;;
            esac
            case "$line" in
                *"]"*) in_members=0 ;;
            esac
        fi
    done < "$toml"
}

# Every crate actually built into the kernel binary should be on exactly one
# side of the partition. `libsys` is the one deliberate exception: it is a
# real workspace member, but it is the ring-3 ABI wrapper linked into
# separate userspace ELF binaries, never into the kernel binary itself, so
# it cannot violate or satisfy this rule either way (see the lists above). A
# member crate on neither list is not a pass: it means this script's
# partition has drifted from the tree, silently, in exactly the way a
# feature flag was rejected for doing.
unlisted=""
for c in $(workspace_member_dirs); do
    case "$c" in
        libsys) continue ;;
    esac
    if ! is_in "$c" "$CORE_CRATES" && ! is_in "$c" "$SCAFFOLD_CRATES" \
       && ! is_in "$c" "$PROFILE_CRATES"; then
        unlisted="${unlisted}  ${c}\n"
    fi
done

echo "Certified-partition check (Q2.1: this is NOT the TCB — see header)"
echo "  core crates:      $(printf '%s' "$CORE_CRATES" | wc -w | tr -d ' ')"
echo "  profile crates:   $(printf '%s' "$PROFILE_CRATES" | wc -w | tr -d ' ')"
echo "  scaffold crates:  $(printf '%s' "$SCAFFOLD_CRATES" | wc -w | tr -d ' ')"
echo "  scaffold violations found: $violations (baseline: $BASELINE_VIOLATIONS)"
echo "  profile violations found: $profile_violations (baseline: $BASELINE_PROFILE_VIOLATIONS)"

status=0

if [ -n "$findings" ]; then
    echo ""
    echo "  core crate -> scaffolding crate edges:"
    printf '%b' "$findings"
fi

if [ -n "$gated_findings" ]; then
    echo ""
    echo "  domain-gated core -> profile edges (optional; linked only by a domain feature):"
    printf '%b' "$gated_findings"
fi

if [ -n "$profile_findings" ]; then
    echo ""
    echo "  core crate -> profile crate edges (Q2.3 — report, do not fix here):"
    printf '%b' "$profile_findings"
fi

if [ -n "$unlisted" ]; then
    echo ""
    echo "  FAIL: crates present in crates/ but not classified on any of the three lists:"
    printf '%b' "$unlisted"
    echo "  Add each one to CORE_CRATES, PROFILE_CRATES, or SCAFFOLD_CRATES in this"
    echo "  script with a one-line reason before trusting this"
    echo "  check again."
    status=1
fi

if [ "$violations" -gt "$BASELINE_VIOLATIONS" ]; then
    echo ""
    echo "  FAIL: $violations scaffold violation(s) > baseline of $BASELINE_VIOLATIONS."
    echo "  A core crate started depending on a scaffolding crate that it did not"
    echo "  depend on before. Either that edge is a mistake (drop it), or it is a"
    echo "  real new requirement — in which case the crate on the scaffolding side"
    echo "  needs to move to core (with its own one-line justification in"
    echo "  this script), not have the baseline quietly bumped to make this pass."
    status=1
elif [ "$violations" -lt "$BASELINE_VIOLATIONS" ]; then
    echo ""
    echo "  ok: $violations scaffold violation(s) < baseline of $BASELINE_VIOLATIONS."
    echo "  One of the known edges (see the header comment) appears to be gone —"
    echo "  this PASSES, but lower BASELINE_VIOLATIONS in this script to match."
    echo "  A stale baseline that only ever gets easier to pass hides the next"
    echo "  regression behind the margin the fixed edge left; it should ratchet"
    echo "  down the moment a fix earns it, not sit at a number nobody re-checks."
else
    echo ""
    echo "  ok: scaffold violation count at baseline ($BASELINE_VIOLATIONS)."
fi

if [ "$profile_violations" -gt "$BASELINE_PROFILE_VIOLATIONS" ]; then
    echo ""
    echo "  FAIL: $profile_violations profile violation(s) > baseline of $BASELINE_PROFILE_VIOLATIONS."
    echo "  A core crate started depending on a profile crate it did not depend on"
    echo "  before (Q2.3: core may not depend on profile). Either drop the edge, or"
    echo "  it is a real new requirement and the dependency needs the trait-inversion"
    echo "  seam Q2.3 calls for — not a bumped baseline."
    status=1
elif [ "$profile_violations" -lt "$BASELINE_PROFILE_VIOLATIONS" ]; then
    echo ""
    echo "  ok: $profile_violations profile violation(s) < baseline of $BASELINE_PROFILE_VIOLATIONS."
    echo "  One of the eight known core -> profile edges appears to be gone — this"
    echo "  PASSES, but lower BASELINE_PROFILE_VIOLATIONS in this script to match,"
    echo "  for the same reason the scaffold baseline above must ratchet down."
else
    echo ""
    echo "  ok: profile violation count at baseline ($BASELINE_PROFILE_VIOLATIONS)."
fi

# ── S-mode lines by crate (Q2.1's second metric) ────────────────────────────
#
# The certified partition above says which crates the project calls "core";
# this says how much of the image that actually is. Every one of these lines
# still runs in S-mode and can write the e-stop latch — moving a crate to
# CORE_CRATES never shrank this number, and moving one OUT of it (as the
# PROFILE split above just did) does not either, until the code actually
# moves to a different privilege level or address space. The number to watch
# is this one, not the crate count above it; Q2.2 picks the first crate to
# make it go down (a placement change, not a re-list).
echo ""
echo "  S-mode lines by crate (core, descending):"
for c in $CORE_CRATES; do
    dir="$(crate_dir "$c")/src"
    [ -d "$dir" ] || continue
    n="$(find "$dir" -name '*.rs' -not -name '* [0-9]*' -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')"
    printf '%s %s\n' "${n:-0}" "$c"
done | sort -rn | awk '{printf "    %6d  %s\n", $1, $2}'

if [ "$status" -eq 0 ]; then
    echo ""
    echo "  ok: certified-partition check passed."
fi

exit "$status"
