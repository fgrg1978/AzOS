#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# The gate's short tiers. `make ci` is the full gate (N2).
#
#   tools/gate/gate_tier.sh n0   `make check` for riscv64, aarch64 and x86_64 (generic, robot, microvm), the
#                           output-dir lint (tools/lint/out_dir_lint.py), the gate
#                           rows manifest (tools/gate/gate_rows.py --check), the
#                           unsafe and size budgets (`make size-check`), plus
#                           cargo-deny (licences, bans, sources; offline), plus
#                           the host suites the diff reaches (`make check0`)
#   tools/gate/gate_tier.sh n1   n0's host suites, then tools/gate/ci_check.sh under
#                           CI_TIER=rows with the per-ISA smoke boots and the
#                           n1 rows the diff maps to (`make check1`)
#   tools/gate/gate_tier.sh compile  the fast per-front check (`make check-compile`): `cargo check`
#                           (validate profile, no codegen) of the kernel cells the diff reaches
#                           (tools/gate/compile_plan.py: ISAs and presets) and `cargo check --tests` of
#                           the host suites it reaches; no lints, no budgets, nothing boots
#   tools/gate/gate_tier.sh lints  n0's lints alone, no build and no host suite: the
#                           full gate's "n0 lints" row, so `make ci` runs the
#                           same lints as `make check0`
#
# The diff is the working tree against GATE_BASE (default HEAD); see
# tools/gate/rows_for_diff.py for how paths map to rows and suites.
# COMPILE_ONLY=1 (n0, n1): the cheap form. The kernel cells are type-checked in the
# `validate` profile (incremental, 16 codegen units) and the host suites are built in it;
# the size budget still builds the one full release kernel, and the lints run. AZOS_SHARED_TARGET
# and AZOS_SCCACHE (tools/gate/validate_env.sh) apply to those type-checks.
# n0 and n1 queue for a host-wide build slot (tools/dev/buildq; BUILDQ=0 skips it).
# GATE_DRY=1 prints what would run and runs nothing.
set -uo pipefail
# qgrep: grep -q at the end of a pipe, safe under pipefail (see tools/gate/ci_check.sh).
qgrep() { local rc; grep "$@"; rc=$?; cat >/dev/null; return "$rc"; }
cd "$(dirname "$0")/../.." || exit 2
tier="${1:-}"
base="${GATE_BASE:-HEAD}"
case "$tier" in n0|n1|lints|compile) ;; *) echo "usage: tools/gate/gate_tier.sh n0|n1|lints|compile"; exit 2 ;; esac
case "$tier" in n0|n1) [ -n "${BUILDQ_HELD:-}" ] || [ "${BUILDQ:-1}" = 0 ] || exec bash tools/dev/buildq bash "$PWD/tools/gate/gate_tier.sh" "$@" ;; esac
lints=0; case "$tier" in n0|lints) lints=1 ;; esac
compile_only=0; { [ "${COMPILE_ONLY:-0}" = 1 ] || [ "$tier" = compile ]; } && compile_only=1
[ "$compile_only" = 1 ] && . tools/gate/validate_env.sh
cprofile=release; [ "$compile_only" = 1 ] && cprofile=validate
# Outputs live under $AZOS_OUT (tools/lib/out_dir.py), never in the checkout.
AZOS_OUT="${AZOS_OUT:-$(python3 tools/lib/out_dir.py)}"; export AZOS_OUT
export TOPOLOGY_PUBKEY_PATH="${TOPOLOGY_PUBKEY_PATH:-$PWD/tools/keys/test_pub.bin}"

# Host suites build azos_limits from a config: a clean checkout has none, and must
# not fail for that.
if [ -z "${KCONFIG_CONFIG:-}" ] && [ ! -f .config ]; then
    KCONFIG_CONFIG="${AZOS_OUT:-out}/gate-tier.config"; export KCONFIG_CONFIG
    mkdir -p "$(dirname "$KCONFIG_CONFIG")"
    cp config/defconfigs/generic-sbc-riscv64-dev+qemu+linux+gui.config "$KCONFIG_CONFIG" && python3 -m olddefconfig >/dev/null 2>&1 || exit 2
fi
suites=""
cells="riscv64 aarch64 x86_64 riscv64:robot aarch64:robot x86_64:robot riscv64:microvm aarch64:microvm x86_64:microvm"
if [ "$tier" = compile ]; then
    plan="$(python3 tools/gate/compile_plan.py --base "$base")" || exit 2
    cells="$(printf '%s\n' "$plan" | awk '$1 == "cell" { print ($3 == "generic") ? $2 : $2 ":" $3 }' | tr '\n' ' ')"
    suites="$(printf '%s\n' "$plan" | awk '$1 == "host" { print $2 }')"
elif [ "$tier" != lints ]; then
    suites="$(python3 tools/gate/rows_for_diff.py --base "$base" --host)" || exit 2
fi
fail=0
t0=$SECONDS

if [ "${GATE_DRY:-0}" = 1 ]; then
    [ "$tier" = compile ] && { echo "cells: ${cells:-none}" | tr '\n' ' '; echo; }
    echo "host suites: ${suites:-none}" | tr '\n' ' '; echo
    [ "$tier" = n1 ] && { echo "rows:"; python3 tools/gate/rows_for_diff.py --base "$base" --rows --explain | sed 's/^/  /'; }
    exit 0
fi

# The gate's own rules: zero warnings for riscv64 and aarch64 but build-script
# notes and the aarch64 build's known noise (A64_KNOWN_NOISE in ci_check.sh);
# the x86_64 skeleton by exit status, as the gate's "x86_64: make check" row.
noise='^warning: [A-Za-z0-9_-]+@[0-9]|prod pubkey|packages contain code that will be rejected by a future version of Rust: core v0\.0\.0'
# Each ISA three times: the generic gate cell, the robot one (the robot crates
# under crates/domains/robot/ and the kernel's `use-robot` code) and the
# microvm one (the cut: no slots, no Linux personality, no physical-hardware drivers).
if [ "$tier" = n0 ] || [ "$tier" = compile ]; then
    for arch in $cells; do
        preset=generic
        case "$arch" in *:*) preset="${arch#*:}"; arch="${arch%%:*}" ;; esac
        printf "  %-26s" "check ${arch}$([ "$preset" != generic ] && echo " $preset")..."
        if out="$(make ARCH="$arch" CHECK_PRESET="$preset" CHECK_PROFILE="$cprofile" check 2>&1)" \
           && { [ "$arch" = x86_64 ] || ! printf '%s\n' "$out" | grep -E '^warning:' | qgrep -qvE "$noise"; }; then
            echo ok
        else
            echo FAIL; fail=1
            printf '%s\n' "$out" | grep -E '^(error|warning)' | sed -n 1,5p | sed 's/^/      /'
        fi
    done

    # The resident monitor (VIRT_SPLIT, aarch64): build the flat image and prove
    # its link invariant (no kernel symbol, a static image), then compile-check
    # the split kernel that `.incbin`s it. ARCH_HAS_HYP_MONITOR is unset, so no
    # Kconfig path reaches the split image; the gate-only `hyp-monitor-row`
    # feature builds it. This is the compile-only proof that the monitor and the
    # split kernel stay buildable; the QEMU rows (R1-R3, R14) run later on arm.
    printf "  %-26s" "hyp-mon build + link lint..."
    if out="$(AZOS_OUT="$AZOS_OUT" bash tools/build/hyp_mon.sh aarch64 \
                 "$AZOS_OUT/build/aarch64/hyp-mon.bin" 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | grep -iE 'error|FAIL' | sed -n 1,5p | sed 's/^/      /'
    fi
    printf "  %-26s" "aarch64 split kernel check..."
    # One target dir per worktree: azos_limits' build script watches the Kconfig
    # files by the path of the tree that built it, so a dir shared between
    # worktrees misses a symbol another tree added.
    splitcfg="$AZOS_OUT/cfg/a64-split.config"
    mkdir -p "$(dirname "$splitcfg")"
    cp config/defconfigs/generic-sbc-aarch64-dev+qemu+linux+gui.config "$splitcfg.base"
    KCONFIG_CONFIG="$splitcfg.base" python3 -m olddefconfig >/dev/null 2>&1
    if sf="$(KCONFIG_CONFIG="$splitcfg.base" python3 tools/build/kconfig_to_cargo.py \
                --select hyp-monitor-row --out "$splitcfg" "$splitcfg.base" 2>&1)" \
       && make ARCH=aarch64 CHECK_PRESET=generic "$AZOS_OUT/build/image_hashes_aarch64.rs" >/dev/null 2>&1 \
       && out="$(env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$splitcfg" \
                 cargo build --release --target aarch64-unknown-none-softfloat -p azos_kernel \
                   --no-default-features --features "${sf##*--features }" \
                   --config 'build.rustflags=["-C","link-arg=-Tarch/aarch64/boot/linker-aarch64.ld"]' \
                   --target-dir "$AZOS_OUT/target/a64-split-$(pwd -P | shasum | cut -c1-8)" 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "${sf:-}" "$out" | grep -E '^error' | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# No host's install paths in the tree (tools/lint/host_paths_lint.py): canary, then the tree.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "host paths lint..."
    if out="$(python3 tools/lint/host_paths_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/host_paths_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# Nothing writes into the checkout (tools/lint/out_dir_lint.py): its canary first,
# then the tree.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "output dir lint..."
    if out="$(python3 tools/lint/out_dir_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/out_dir_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# The OS does not depend on the companion repo (tools/lint/companion_dep_lint.py): its canary first, then the tree.
# `make check0-nocompanion` runs this whole tier with the repo hidden.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "companion dependency lint..."
    if out="$(python3 tools/lint/companion_dep_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/companion_dep_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# The MMIO accessor lint (tools/lint/mmio_accessors.py), as the gate's row does.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "mmio accessors lint..."
    if out="$(python3 tools/lint/mmio_accessors.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/mmio_accessors.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# The page-table write lint (tools/lint/pt_writes_lint.py), as the gate's row does.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "pt writes lint..."
    if out="$(python3 tools/lint/pt_writes_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/pt_writes_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# The BTI landing-pad lint (tools/lint/bti_pads_lint.py): aarch64 assembly indirect-branch targets.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "bti pads lint..."
    if out="$(python3 tools/lint/bti_pads_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/bti_pads_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# The boot sequence lint (tools/lint/boot_seq_lint.py), as the gate's row does.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "boot seq lint..."
    if out="$(python3 tools/lint/boot_seq_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/boot_seq_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# Kernel task placement (tools/lint/task_place_lint.py), as the gate's row does.
if [ "$tier" = n0 ]; then
    printf "  %-26s" "task place lint..."
    if out="$(python3 tools/lint/task_place_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/task_place_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# Facade bypass ratchet (tools/lint/arch_cfg_lint.py --facade): shared code may not
# reach ISA-specific azos_arch modules (csr, sbi, sysregs, irq::<chip>, ...);
# per-file counts in the [facade] section of tools/lint/arch_cfg_lint.baseline.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "facade bypass..."
    if out="$(python3 tools/lint/arch_cfg_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/arch_cfg_lint.py --facade 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# The trap layer is written once (tools/lint/trap_lint.py): no dispatch logic in entry/<isa>/, a case for every syscall number.
[ "$lints" = 1 ] && { printf "  %-26s" "trap layer lint..."; if out="$(python3 tools/lint/trap_lint.py --self-test 2>&1 && python3 tools/lint/trap_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }

# The three ISAs share one file layout (tools/lint/arch_layout_lint.py): same module set, ISA-only code under ext/.
[ "$lints" = 1 ] && { printf "  %-26s" "arch layout lint..."; if out="$(python3 tools/lint/arch_layout_lint.py --self-test 2>&1 && python3 tools/lint/arch_layout_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# No `allow(dead_code)` in kernel/ or crates/core/ without a `// reason:` (tools/lint/dead_code_lint.py).
[ "$lints" = 1 ] && { printf "  %-26s" "dead code lint..."; if out="$(python3 tools/lint/dead_code_lint.py --self-test 2>&1 && python3 tools/lint/dead_code_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
[ "$lints" = 1 ] && { printf "  %-26s" "neverallow presets..."; if out="$(python3 tools/lint/check_neverallow.py 2>&1 && python3 tools/lint/check_neverallow.py --canary 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# A kernel with no personality (Kconfig LINUX_ABI off) depends on no Linux crate
# on any ISA (`cargo tree`, nothing built; the self-test sees it with the gate's cell).
# Every build selection the gate names is one `--select` accepts (tools/lint/gate_select_lint.py).
[ "$lints" = 1 ] && { printf "  %-26s" "gate selections..."; if out="$(python3 tools/lint/gate_select_lint.py --self-test 2>&1 && python3 tools/lint/gate_select_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
[ "$lints" = 1 ] && { printf "  %-26s" "profile-cut lint..."; if out="$(python3 tools/lint/profile_cut_lint.py --self-test 2>&1 && python3 tools/lint/profile_cut_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# An extension is what its Kconfig symbol, its manifest and its install say, and the base names no extension crate outside a `use-robot` item.
[ "$lints" = 1 ] && { printf "  %-26s" "extension lint..."; if out="$(python3 tools/lint/extension_lint.py --self-test 2>&1 && python3 tools/lint/extension_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# No linker script and no per-crate cargo config under userspace/, one target spec per ISA (sdk/targets).
[ "$lints" = 1 ] && { printf "  %-26s" "user image layout lint..."; if out="$(python3 tools/lint/user_entry_lint.py --self-test 2>&1 && python3 tools/lint/user_entry_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
[ "$lints" = 1 ] && { printf "  %-26s" "doc lint..."; if out="$(python3 tools/lint/doc_lint.py --self-test 2>&1 && python3 tools/lint/doc_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
[ "$lints" = 1 ] && { printf "  %-26s" "tools layout lint..."; if out="$(python3 tools/lint/tools_layout.py --self-test 2>&1 && python3 tools/lint/tools_layout.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# The OTA sender (tools/dev/ota_send.py) against a localhost receiver: one robot, a fleet, a sick canary.
[ "$lints" = 1 ] && { printf "  %-26s" "ota sender self-test..."; if out="$(python3 tools/dev/ota_send.py --self-test 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# The build queue (tools/dev/buildq: slots, stale-slot reclaim, release on signal) and the fast check's planner.
[ "$lints" = 1 ] && { printf "  %-26s" "buildq, compile plan..."; if out="$(bash tools/dev/buildq --self-test 2>&1 && python3 tools/gate/compile_plan.py --self-test 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# The gate scripts parse: a broken continuation makes every row unrunnable,
# and nothing else in n0 runs them.
[ "$lints" = 1 ] && { printf "  %-26s" "gate scripts parse..."; if out="$(for f in tools/gate/*.sh; do bash -n "$f" 2>&1 || echo "  in $f"; done)" && [ -z "$out" ]; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
[ "$lints" = 1 ] && { printf "  %-26s" "req trace lint..."; if out="$(python3 tools/lint/req_trace.py --self-test 2>&1 && python3 tools/lint/req_trace.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# The gate's row manifest (tools/gate/gate_rows.py --check: every row listed, its deps cover what it
# reads) and the diff-to-rows map that reads it (tools/gate/rows_for_diff.py), after their canaries.
[ "$lints" = 1 ] && { printf "  %-26s" "gate rows manifest..."; if out="$(python3 tools/gate/rows_for_diff.py --self-test 2>&1 && python3 tools/gate/gate_rows.py --self-test 2>&1 && python3 tools/gate/gate_rows.py --check 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | grep -v ': ok' | sed -n 1,5p | sed 's/^/      /'; fi; }

# The clean-console judge (tools/gate/console_judge.py: its classes and allowlist, tools/gate/console_allow.tsv: every
# row-specific entry names a row of the manifest) and the `make defconfig` menu with its green cells
# (tools/build/defconfig_menu.py: each names a gate row that exists).
[ "$lints" = 1 ] && { printf "  %-26s" "console judge lint..."; if out="$(python3 tools/gate/console_judge.py --self-test 2>&1 && python3 tools/gate/console_judge.py check 2>&1 && python3 tools/build/defconfig_menu.py --self-test 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }

# The Kconfig option index (tools/build/gen_config_index.py --check: Documentation/config.md's table
# is what the Kconfig tree declares; regenerate with it when a symbol changes), the Zbc CRC fold constants crates/drivers/lx/glue/lxbase.c carries
# (tools/build/lx_kbuild/zbc_crc_constants.py), and the absolute-claim scanner (tools/lint/claims_check.sh,
# a review aid: its self-test only, the scan of the tree is by hand).
[ "$lints" = 1 ] && { printf "  %-26s" "config index..."; if out="$(python3 tools/build/gen_config_index.py --self-test 2>&1 && python3 tools/build/gen_config_index.py --check 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# The companion's constant mirror (tools/build/export_kernel_consts.py): every symbol it exports is still declared.
[ "$lints" = 1 ] && { printf "  %-26s" "kernel consts export..."; if out="$(python3 tools/build/export_kernel_consts.py --self-test 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
[ "$lints" = 1 ] && { printf "  %-26s" "zbc crc constants..."; if out="$(python3 tools/build/lx_kbuild/zbc_crc_constants.py --self-test 2>&1 && python3 tools/build/lx_kbuild/zbc_crc_constants.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | grep -v '^ZBC_' | sed -n 1,5p | sed 's/^/      /'; fi; }
[ "$lints" = 1 ] && { printf "  %-26s" "claims scanner..."; if out="$(bash tools/lint/claims_check.sh --self-test 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }
# The board image's ELF list (tools/image/test_board_manifest.py): an orphan service (declared, not built
# or not shipped) and an orphan ELF (on the disk, not declared); "board: volume = topology" boots only the good case.
[ "$lints" = 1 ] && { printf "  %-26s" "board manifest..."; if out="$(python3 tools/image/test_board_manifest.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | grep -E '^(FAIL|ERROR)|Error' | sed -n 1,5p | sed 's/^/      /'; fi; }

# The ring-3 images follow the .config (tools/image/test_user_images.py): an image off in it is on no digest table and no system volume.
[ "$lints" = 1 ] && { printf "  %-26s" "user images..."; if out="$(python3 tools/image/test_user_images.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | grep -E '^FAIL' | sed -n 1,5p | sed 's/^/      /'; fi; }

# The TPM floor holds epochs up to FLOOR_MAX: the signing tool refuses a bundle above it (tools/sign/test_sign_ota_epoch.py); the canary signs one.
[ "$lints" = 1 ] && { printf "  %-26s" "ota epoch cap..."; if out="$(python3 tools/sign/test_sign_ota_epoch.py 2>&1 && python3 tools/sign/test_sign_ota_epoch.py --canary 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }

# The SDK is keyed by what changes its bytes (tools/build/test_sdk_build.py; --build builds it and is run by hand).
[ "$lints" = 1 ] && { printf "  %-26s" "sdk keys..."; if out="$(python3 tools/build/test_sdk_build.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | grep -E '^FAIL' | sed -n 1,5p | sed 's/^/      /'; fi; }

# Kconfig is the only source of truth (tools/lint/kconfig_lint.py): cargo-feature
# tags against kernel/Cargo.toml, no `select` of a visible symbol.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "kconfig lint..."
    if out="$(python3 tools/lint/kconfig_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/kconfig_lint.py 2>&1 | grep -v '^REPORT')" \
       && ! printf '%s\n' "$out" | grep -q '^ERROR'; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# No build names a kernel feature by hand (tools/lint/feature_source_lint.py): the
# features come from kconfig_to_cargo.py, a build's extras are a --select.
[ "$tier" = n0 ] && { printf "  %-26s" "feature source lint..."; if out="$(python3 tools/lint/feature_source_lint.py --self-test 2>&1 && python3 tools/lint/feature_source_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }

# The generic idle seam is not named after one ISA's instruction
# (tools/lint/isa_neutral_names.py: Cpu::wait_for_interrupt, IdleChoice::Shallow).
[ "$tier" = n0 ] && { printf "  %-26s" "isa-neutral names lint..."; if out="$(python3 tools/lint/isa_neutral_names.py --self-test 2>&1 && python3 tools/lint/isa_neutral_names.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }

# Every aarch64 QEMU line of the gate goes through tools/gate/qemu_a64.py, which picks
# HVF or TCG (tools/lint/qemu_accel_lint.py): the rows that need TCG are tagged or detected.
[ "$tier" = n0 ] && { printf "  %-26s" "arm accelerator lint..."; if out="$(python3 tools/lint/qemu_accel_lint.py --self-test 2>&1 && python3 tools/lint/qemu_accel_lint.py 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'; fi; }

# The unsafe budget (tools/lint/unsafe_budget.py): a crate may not carry more
# `unsafe` than tools/lint/unsafe_budget.tsv says, lose its #![forbid(unsafe_code)],
# or (a kernel crate) raise its share of code lines in files with unsafe; the
# baseline moves in the same commit as the code.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "unsafe budget..."
    if out="$(python3 tools/lint/unsafe_budget.py --self-test 2>&1)" \
       && out="$(python3 tools/lint/unsafe_budget.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# The size budget (tools/lint/size_budget.py): the riscv64 QEMU defconfig kernel
# (`make size-check`) and the x86_64 and aarch64 microvm kernels
# (`make size-check-microvm`), build only, have the .text/.rodata/.data/.bss
# tools/lint/size_budget.tsv says, within its tolerance.
if [ "$tier" = n0 ]; then
    printf "  %-26s" "size budget..."
    if out="$(make -s size-check 2>&1 && make -s size-check-microvm 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | grep -E '^(FAIL|error|size_budget|update)' | sed -n 1,6p | sed 's/^/      /'
    fi
fi

# Every preset expands on every ISA (tools/lint/check_presets.py, about 3 s).
if [ "$lints" = 1 ]; then
    printf "  %-26s" "presets..."
    if out="$(python3 tools/lint/check_presets.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# No merge leftovers: a tracked file (vendored third_party/ aside) holds no line
# that starts a conflict marker.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "conflict markers..."
    if out="$(git grep -nE '^(<<<<<<<|>>>>>>>) ' -- . ':!third_party' 2>/dev/null)"; then
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,6p | sed 's/^/      /'
    else
        echo ok
    fi
fi

# Every tracked source file carries its SPDX licence header (tools/lint/spdx_headers.py;
# run it without --check to add the missing ones).
if [ "$lints" = 1 ]; then
    printf "  %-26s" "spdx headers..."
    if out="$(python3 tools/lint/spdx_headers.py --check 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,6p | sed 's/^/      /'
    fi
fi

# The committed OS feature matrix is what the Kconfig tree yields
# (tools/build/gen_feature_matrix.py; regenerate with it when a symbol or a defconfig changes).
if [ "$lints" = 1 ]; then
    printf "  %-26s" "feature matrix..."
    if out="$(python3 tools/build/gen_feature_matrix.py --self-test 2>&1 && python3 tools/build/gen_feature_matrix.py --check 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi


# The committed defconfigs are what their fragments assemble, and each keeps
# the axes its name gives (tools/build/gen_defconfigs.py; `make defconfigs` rewrites them).
if [ "$lints" = 1 ]; then
    printf "  %-26s" "defconfigs from fragments..."
    if out="$(python3 tools/build/gen_defconfigs.py --self-test 2>&1 && python3 tools/build/gen_defconfigs.py --check 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# `make defconfig`'s menu assembles every preset on every ISA, and the recovery
# console's prompt is the preset's, matched by the gate's RECOVERY_PROMPT_RE.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "defconfig menu, prompt..."
    if out="$(python3 tools/build/defconfig_menu.py --self-test 2>&1 && python3 tools/build/test_preset_prompt.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | grep -E 'FAIL|Error' | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# A ring-3 image takes its codegen flags from a configuration of its own ISA, whatever ISA
# .config selects and whatever an earlier make left in the output directory.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "user image ISA..."
    if out="$(python3 tools/build/test_user_isa.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | grep FAIL | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# `make help` must not name a target the Makefile lacks (tools/lint/check_make_help.sh).
if [ "$lints" = 1 ]; then
    printf "  %-26s" "make help targets..."
    if out="$(bash tools/lint/check_make_help.sh 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# Supply chain (deny.toml): licences, bans and sources of the registry crates
# the kernel links, offline (metadata from cargo; the advisories are the next row).
if [ "$lints" = 1 ]; then
    printf "  %-26s" "cargo deny..."
    mkdir -p "$AZOS_OUT/build"; dmd="$AZOS_OUT/build/deny-metadata.json"
    if out="$(cargo metadata --offline --locked --format-version 1 2>&1 >"$dmd")" \
       && out="$(cargo deny check --metadata-path "$dmd" --disable-fetch licenses bans sources 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | grep -E '^(error|warning)' | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# Third-party pins: third_party/MANIFEST.json against .gitmodules and the index, VENDOR_PIN well formed,
# and no pin below a fixed_in version of third_party/known_cves.tsv (tools/lint/third_party_versions.py).
if [ "$lints" = 1 ]; then
    printf "  %-26s" "third_party versions..."
    if out="$(python3 tools/lint/third_party_versions.py --self-test 2>&1 && python3 tools/lint/third_party_versions.py --quiet 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,6p | sed 's/^/      /'
    fi
fi

# The external inventory of `make fetch` (tools/build/fetch.py): the config -> trees mapping, the pin rewrite on a
# temp copy, and a scan that holds every download and tool the scripts call to an inventory item. Offline.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "fetch inventory..."
    if out="$(python3 tools/build/fetch.py self-test 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,8p | sed 's/^/      /'
    fi
fi

# RustSec advisories for every registry crate any lockfile resolves, against the
# dated snapshot in third_party/advisory-db (tools/lint/advisories.sh; `make advisories-update`
# refreshes it by hand). A missing or old snapshot, or a lockfile that does not resolve, is a WARN line.
if [ "$lints" = 1 ]; then
    printf "  %-26s" "advisories..."
    out="$(bash tools/lint/advisories.sh check 2>&1)"; rc=$?
    if [ "$rc" = 0 ]; then
        if printf '%s\n' "$out" | grep -q '^WARN'; then
            echo WARN
            printf '%s\n' "$out" | sed -n 1,4p | sed 's/^/      /'
        else
            echo ok
        fi
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,14p | sed 's/^/      /'
    fi
fi

# The seccomp suite reads the digest table, which binds the images the .config enables, and boots test
# programs among them: it is made from the gate's configuration, which asks for all of them
# (tools/build/gen_userspace_kconfig.py --all-on), whatever the last `make` here was.
# syscall-tests compiles in $AZOS_OUT/build/uhello.elf and checks its digest against the table
# (image_binding.rs): it needs the same table and the same uhello.elf, made together here, not
# whatever an earlier `make` (size-update, a row) left in $AZOS_OUT/build.
case " $suites " in *seccomp-tests*|*syscall-tests*)
    printf "  %-26s" "image table (all on)..."
    if out="$(make host-image-table 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "${out:-}" | grep -E '^(make|error)|\*\*\*' | sed -n 1,5p | sed 's/^/      /'
    fi ;;
esac
# micro/build.rs reads $AZOS_OUT/build/micro.config, which ci_check.sh makes; do it here too.
case " $suites " in *micro-tests*) make -s micro-config </dev/null >/dev/null 2>&1 ;; esac
# lx-loader-tests reads the lxtest modules from $AZOS_OUT/build/lx (`make lx-modules`), as its gate row builds them.
case " $suites " in *lx-loader-tests*) make -s lx-modules </dev/null >/dev/null 2>&1 ;; esac
for s in $suites; do
    printf "  %-26s" "host ${s#tests/host/}..."
    kc=""; case "$s" in *micro-tests) kc="$AZOS_OUT/build/micro.config" ;; esac
    # compile: `cargo check --tests` (nothing runs); COMPILE_ONLY: the tests run, built in the validate profile.
    case "$tier:$compile_only" in
        compile:*) hcmd="cargo check --tests --profile validate" ;;
        *:1) hcmd="cargo test --profile validate" ;;
        *) hcmd="cargo test --release" ;;
    esac
    if out="$(cd "$s" && env CARGO_TARGET_DIR="$AZOS_OUT/tgt/$s" ${kc:+KCONFIG_CONFIG=$kc} $hcmd 2>&1)" \
       && ! printf '%s\n' "$out" | qgrep -q 'test result: FAILED' \
       && ! printf '%s\n' "$out" | qgrep -qE '^warning: .*generated'; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | grep -E '^(error|warning)|test result|panicked' | sed -n 1,5p | sed 's/^/      /'
    fi
done

if [ "$tier" = n1 ]; then
    rows="$(python3 tools/gate/rows_for_diff.py --base "$base" --rows)" || exit 2
    CI_TIER=rows CI_ROWS="$rows" bash tools/gate/ci_check.sh || fail=1
fi

echo "gate_tier ${tier}: $((SECONDS - t0)) s, $([ "$fail" = 0 ] && echo green || echo RED)"
exit "$fail"
