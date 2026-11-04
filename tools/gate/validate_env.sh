# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Sourced by validation builds only (`make check-compile`, `make check0 COMPILE_ONLY=1`):
# the environment that makes them cheaper. Nothing here reaches a build that makes
# an image, the size or unsafe budget, vsbench or a gate row: those do not source it.
#
#   CHECK_PROFILE=validate   the type-check uses the `validate` profile (.cargo/config.toml)
#   AZOS_SHARED_TARGET=<dir> opt-in: type-checks of every checkout use <dir>/check-<isa>
#                            as their target dir, so build-std (core, alloc,
#                            compiler_builtins) and the crates.io dependencies are
#                            built once per ISA. Units of this checkout's own
#                            packages are tagged with `--cfg azos_wt=<id>`
#                            (-Zprofile-rustflags, `make check`'s CHECK_CARGO_CONFIG: the workspace
#                            members', not build-std's or crates.io's), so two checkouts' crates never
#                            share a cargo unit: cargo's staleness check compares file mtimes,
#                            and would take another checkout's older artifact for fresh.
#   AZOS_SCCACHE=1           opt-in: RUSTC_WRAPPER=sccache for those type-checks
#                            (SCCACHE_DIR defaults to $HOME/azos-out/sccache, 4G). Ring-3 builds
#                            set their own wrapper on the command line and are not affected.
export CHECK_PROFILE=validate
if [ -n "${AZOS_SHARED_TARGET:-}" ]; then
    mkdir -p "$AZOS_SHARED_TARGET"
    export AZOS_SHARED_TARGET
    export AZOS_WT_TAG="$(basename "$PWD")-$(printf %s "$(pwd -P)" | shasum | cut -c1-8)"
fi
if [ "${AZOS_SCCACHE:-0}" = 1 ]; then
    if command -v sccache >/dev/null 2>&1; then
        export RUSTC_WRAPPER="$(command -v sccache)"
        export SCCACHE_DIR="${SCCACHE_DIR:-$HOME/azos-out/sccache}" SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-4G}"
    else
        echo "validate_env: AZOS_SCCACHE=1 but sccache is not on PATH; building without it" >&2
    fi
fi
