#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_kconfig_to_cargo.py — RFC-0026 Phase C4 bridge-script unit tests.

Verifies that tools/kconfig_to_cargo.py:
  1. Emits a valid --target triple for every defconfig.
  2. Emits ONLY cargo features that exist in kernel/Cargo.toml [features] OR
     in a named sub-crate as a "crate/feat" token.
  3. Does NOT emit phantom features (brain-l1, brain-l2, brain-l3, etc.).
  4. Emits the correct target triple per architecture.
  5. Handles the inverted no-ml mapping correctly.

Run with:
    python3 tools/test_kconfig_to_cargo.py

Or via pytest:
    python3 -m pytest tools/test_kconfig_to_cargo.py -v
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Locate repo root relative to this script.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.resolve()
TOOLS_DIR = REPO_ROOT / "tools"
DEFCONFIGS_DIR = REPO_ROOT / "config" / "defconfigs"
KERNEL_CARGO_TOML = REPO_ROOT / "kernel" / "Cargo.toml"

# ---------------------------------------------------------------------------
# Parse kernel/Cargo.toml to get the valid bare feature names.
# ---------------------------------------------------------------------------

def parse_kernel_features(cargo_toml_path: Path) -> frozenset[str]:
    """Extract feature names from the [features] block of kernel/Cargo.toml.

    Uses a regex; no toml dependency needed.  Returns a frozenset of bare
    feature names (e.g. {'vf2', 'k1', 'qemu', 'no-ml', ...}).
    """
    text = cargo_toml_path.read_text(encoding="utf-8")
    # Find the [features] block: everything between [features] and the next [...]
    features_block_match = re.search(
        r"^\[features\](.*?)^(?=\[)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not features_block_match:
        raise RuntimeError(f"No [features] block found in {cargo_toml_path}")

    features_block = features_block_match.group(1)
    # Each feature line starts with an identifier (may contain hyphens/underscores).
    names = re.findall(r"^([a-zA-Z][a-zA-Z0-9_\-]+)\s*=", features_block, re.MULTILINE)
    return frozenset(names)


# ---------------------------------------------------------------------------
# Known valid sub-crate feature tokens (crate/feat form).
# These are verified manually against the crate Cargo.toml files.
# ---------------------------------------------------------------------------

VALID_CRATE_FEATURES: frozenset[str] = frozenset({
    # None today. `azos_mm/small-mem` was the last one; the bridge no
    # longer emits it (see test_no_config_emits_small_mem).
})

# ---------------------------------------------------------------------------
# Valid target triples
# ---------------------------------------------------------------------------

VALID_TARGETS: frozenset[str] = frozenset({
    "riscv64imac-unknown-none-elf",
    "aarch64-unknown-none-softfloat",
    "x86_64-unknown-none",
})

# ---------------------------------------------------------------------------
# Known phantom features that must NEVER appear in output.
# These existed in the C1 script's generic _ENABLED path.
# ---------------------------------------------------------------------------

PHANTOM_FEATURES: frozenset[str] = frozenset({
    "brain-l1",
    "brain-l2",
    "brain-l3",
    "auto-reconnect",
})

# ---------------------------------------------------------------------------
# Expected outputs per defconfig (target, features subset that must be present)
# ---------------------------------------------------------------------------

# Each entry: (defconfig_stem, expected_target, must_include_features,
#              must_exclude_features)
DEFCONFIG_EXPECTATIONS: list[tuple[str, str, set[str], set[str]]] = [
    # edge — all defaults, riscv64 QEMU, no features override
    (
        "edge",
        "riscv64imac-unknown-none-elf",
        set(),                              # no features required
        {"vf2", "k1", "no-ml", "no-mmu"},  # must not appear
    ),
    # qemu — identical to edge (explicit alias)
    (
        "qemu",
        "riscv64imac-unknown-none-elf",
        set(),
        {"vf2", "k1", "no-ml", "no-mmu"},
    ),
    # vf2 — must emit vf2 feature
    (
        "vf2",
        "riscv64imac-unknown-none-elf",
        {"vf2"},
        {"k1", "no-ml", "no-mmu"},
    ),
    # k1 — must emit k1 feature
    (
        "k1",
        "riscv64imac-unknown-none-elf",
        {"k1"},
        {"vf2", "no-ml", "no-mmu"},
    ),
    # embedded — no cargo feature at all: its sizing is constants only, and
    # small-mem (PMM capped at 128 pages) must not come back
    (
        "embedded",
        "riscv64imac-unknown-none-elf",
        set(),
        {"azos_mm/small-mem", "vf2", "k1", "qemu", "no-ml", "no-mmu"},
    ),
    # fleet — all defaults, large caps via constants (no cargo features)
    (
        "fleet",
        "riscv64imac-unknown-none-elf",
        set(),
        {"vf2", "k1", "no-ml", "no-mmu"},
    ),
    # qemu-aarch64 — must emit aarch64 target
    (
        "qemu-aarch64",
        "aarch64-unknown-none-softfloat",
        set(),
        {"vf2", "k1", "no-ml", "no-mmu"},
    ),
]


# ---------------------------------------------------------------------------
# Helper: run the bridge script against a defconfig path
# ---------------------------------------------------------------------------

def run_bridge(defconfig_path: Path) -> str:
    """Run kconfig_to_cargo.py against the given defconfig and return stdout."""
    script = TOOLS_DIR / "kconfig_to_cargo.py"
    result = subprocess.run(
        [sys.executable, str(script), str(defconfig_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"kconfig_to_cargo.py exited {result.returncode} for {defconfig_path}:\n"
        f"{result.stderr}"
    )
    return result.stdout.strip()


def parse_output(output: str) -> tuple[Optional[str], list[str]]:
    """Split bridge output into (target_triple, feature_list).

    Returns (None, []) when output is empty (no .config present).
    Returns (target, [feat, ...]) otherwise.
    """
    if not output:
        return None, []

    target: Optional[str] = None
    features: list[str] = []

    # Split on whitespace tokens
    parts = output.split()
    i = 0
    while i < len(parts):
        if parts[i] == "--target" and i + 1 < len(parts):
            target = parts[i + 1]
            i += 2
        elif parts[i] == "--features" and i + 1 < len(parts):
            features = parts[i + 1].split(",")
            i += 2
        else:
            i += 1

    return target, features


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_kernel_features_parseable() -> None:
    """Smoke test: we can parse kernel/Cargo.toml features block."""
    feats = parse_kernel_features(KERNEL_CARGO_TOML)
    # Known features that must be present
    for expected in ("vf2", "k1", "qemu", "no-ml", "no-mmu",
                     "rvv", "tftp-smoke",
                     "secure-boot-enforced"):
        assert expected in feats, f"Expected feature '{expected}' missing from kernel/Cargo.toml"


def test_no_phantom_features() -> None:
    """Phantom features (brain-l1/l2/l3) must never appear in any output."""
    KERNEL_FEATURES = parse_kernel_features(KERNEL_CARGO_TOML)

    for defconfig_name, _expected_target, _must_include, _must_exclude in DEFCONFIG_EXPECTATIONS:
        defconfig_path = DEFCONFIGS_DIR / f"{defconfig_name}.config"
        assert defconfig_path.exists(), f"defconfig not found: {defconfig_path}"

        output = run_bridge(defconfig_path)
        _target, features = parse_output(output)

        for feat in features:
            assert feat not in PHANTOM_FEATURES, (
                f"defconfig={defconfig_name}: phantom feature '{feat}' emitted"
            )


def test_all_emitted_features_are_valid() -> None:
    """Every emitted feature must be in kernel/Cargo.toml or a known crate/feat token."""
    KERNEL_FEATURES = parse_kernel_features(KERNEL_CARGO_TOML)

    for defconfig_name, _expected_target, _must_include, _must_exclude in DEFCONFIG_EXPECTATIONS:
        defconfig_path = DEFCONFIGS_DIR / f"{defconfig_name}.config"
        output = run_bridge(defconfig_path)
        _target, features = parse_output(output)

        for feat in features:
            is_bare_valid = feat in KERNEL_FEATURES
            is_crate_valid = feat in VALID_CRATE_FEATURES
            assert is_bare_valid or is_crate_valid, (
                f"defconfig={defconfig_name}: feature '{feat}' is not in "
                f"kernel/Cargo.toml [features] and is not a known crate/feat token"
            )


def test_target_triples_are_valid() -> None:
    """Every defconfig must emit one of the 3 valid target triples."""
    for defconfig_name, expected_target, _must_include, _must_exclude in DEFCONFIG_EXPECTATIONS:
        defconfig_path = DEFCONFIGS_DIR / f"{defconfig_name}.config"
        output = run_bridge(defconfig_path)
        target, _features = parse_output(output)

        assert target is not None, (
            f"defconfig={defconfig_name}: no --target in output: '{output}'"
        )
        assert target in VALID_TARGETS, (
            f"defconfig={defconfig_name}: invalid target '{target}'"
        )
        assert target == expected_target, (
            f"defconfig={defconfig_name}: expected target '{expected_target}', "
            f"got '{target}'"
        )


def test_expected_features_present_and_absent() -> None:
    """For each defconfig, verify must_include and must_exclude feature sets."""
    for defconfig_name, _target, must_include, must_exclude in DEFCONFIG_EXPECTATIONS:
        defconfig_path = DEFCONFIGS_DIR / f"{defconfig_name}.config"
        output = run_bridge(defconfig_path)
        _target_triple, features = parse_output(output)
        feat_set = set(features)

        for feat in must_include:
            assert feat in feat_set, (
                f"defconfig={defconfig_name}: required feature '{feat}' not emitted. "
                f"Got: {sorted(feat_set)}"
            )
        for feat in must_exclude:
            assert feat not in feat_set, (
                f"defconfig={defconfig_name}: excluded feature '{feat}' was emitted. "
                f"Got: {sorted(feat_set)}"
            )


def test_missing_dot_config_emits_nothing() -> None:
    """When .config is absent, script must emit nothing (exit 0)."""
    script = TOOLS_DIR / "kconfig_to_cargo.py"
    result = subprocess.run(
        [sys.executable, str(script), "/nonexistent/path/.config"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "", (
        f"Expected empty output for absent .config; got: '{result.stdout.strip()}'"
    )


def test_edge_no_ml_absent() -> None:
    """edge defconfig does not disable DRV_ML_INFERENCE → no-ml must NOT appear."""
    defconfig_path = DEFCONFIGS_DIR / "edge.config"
    output = run_bridge(defconfig_path)
    _target, features = parse_output(output)
    assert "no-ml" not in features, (
        f"edge defconfig should NOT emit no-ml; got features: {features}"
    )


def test_aarch64_target_selection() -> None:
    """qemu-aarch64 defconfig must select aarch64-unknown-none-softfloat.

    The aarch64 KERNEL is FP-free (lazy user FP); userspace stays hard-float
    and is not built through this bridge.
    """
    defconfig_path = DEFCONFIGS_DIR / "qemu-aarch64.config"
    output = run_bridge(defconfig_path)
    target, _features = parse_output(output)
    assert target == "aarch64-unknown-none-softfloat", (
        f"Expected aarch64 target; got '{target}'"
    )


def _bridge_features_for(lines: list[str], tmp_dir: Path) -> list[str]:
    """Write `lines` as a .config under tmp_dir and return the bridge's features."""
    cfg = tmp_dir / "synthetic.config"
    cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _target, features = parse_output(run_bridge(cfg))
    return features


def test_no_config_emits_small_mem() -> None:
    """No profile or board combination may emit azos_mm/small-mem.

    small-mem capped the PMM at 128 pages (512 KiB) whatever the RAM; `init`
    reserved the image inside those pages and was left with none free. The
    PMM ceiling comes from RAM_SIZE on every profile now. The embedded profile
    is checked alone and on each board, since the old row keyed on the profile
    and ignored the board.
    """
    import tempfile

    profiles = ["CONFIG_PROFILE_EMBEDDED=y", "CONFIG_PROFILE_EDGE=y", "CONFIG_PROFILE_FLEET=y"]
    boards = [None, "CONFIG_BOARD_GENERIC=y", "CONFIG_BOARD_QEMU=y",
              "CONFIG_BOARD_VF2=y", "CONFIG_BOARD_K1=y"]
    with tempfile.TemporaryDirectory() as td:
        for profile in profiles:
            for board in boards:
                lines = [profile] + ([board] if board else [])
                features = _bridge_features_for(lines, Path(td))
                offending = [f for f in features if "small-mem" in f]
                assert not offending, (
                    f"config {lines}: emitted {offending}; the PMM must be sized "
                    f"from RAM_SIZE, not capped by small-mem"
                )


def test_embedded_ram_size_comes_through() -> None:
    """config/defconfigs/embedded.config expands to RAM_SIZE=64 and the embedded profile.

    RAM_SIZE is the PMM bitmap ceiling (crates/core/mm/src/pmm.rs MAX_PAGES). The
    generic board's default is 256 (config/Kconfig.platform), so the value has to
    survive olddefconfig from the defconfig itself. The expansion runs in a
    temporary directory through KCONFIG_CONFIG, the way the gate expands the
    fleet defconfig, and never touches the workspace .config.
    """
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "embedded.config"
        shutil.copyfile(DEFCONFIGS_DIR / "embedded.config", cfg)
        env = dict(os.environ, KCONFIG_CONFIG=str(cfg))
        result = subprocess.run(
            [sys.executable, "-m", "olddefconfig"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"olddefconfig failed on config/defconfigs/embedded.config "
            f"(kconfiglib is required, as for the gate's fleet row):\n{result.stderr}"
        )
        expanded = cfg.read_text(encoding="utf-8").splitlines()
        assert "CONFIG_PROFILE_EMBEDDED=y" in expanded, "embedded profile lost in expansion"
        ram = [l for l in expanded if l.startswith("CONFIG_RAM_SIZE=")]
        assert ram == ["CONFIG_RAM_SIZE=64"], (
            f"expanded embedded config carries {ram}, expected ['CONFIG_RAM_SIZE=64']"
        )
        _target, features = parse_output(run_bridge(cfg))
        # The embedded profile is Generic (wave 11, owner decision): no board
        # feature, the kernel's defaults without `domain-robot`.
        want = [f for f in _kernel_default_features() if f != "domain-robot"]
        assert features == want, (
            f"expanded embedded config emitted features {features}; expected {want}"
        )


def test_fleet_ram_size_holds_the_heap() -> None:
    """config/defconfigs/fleet.config expands to RAM_SIZE=1024.

    The page allocator stops at RAM_SIZE, and the fleet heap (256 MiB) is taken
    from it after a ~134 MiB image. At the generic board's default of 256 the
    boot stopped at "[MM] Heap FAILED:". Expanded the same way as the embedded
    defconfig above, in a temporary directory.
    """
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "fleet.config"
        shutil.copyfile(DEFCONFIGS_DIR / "fleet.config", cfg)
        env = dict(os.environ, KCONFIG_CONFIG=str(cfg))
        result = subprocess.run(
            [sys.executable, "-m", "olddefconfig"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"olddefconfig failed on config/defconfigs/fleet.config:\n{result.stderr}"
        )
        expanded = cfg.read_text(encoding="utf-8").splitlines()
        assert "CONFIG_PROFILE_FLEET=y" in expanded, "fleet profile lost in expansion"
        ram = [l for l in expanded if l.startswith("CONFIG_RAM_SIZE=")]
        assert ram == ["CONFIG_RAM_SIZE=1024"], (
            f"expanded fleet config carries {ram}, expected ['CONFIG_RAM_SIZE=1024']"
        )
        heap = [l for l in expanded if l.startswith("CONFIG_KERNEL_HEAP_SIZE=")]
        assert len(heap) == 1 and int(heap[0].split("=")[1]) < 1024 * 1024, (
            f"expanded fleet heap {heap} does not fit below RAM_SIZE"
        )


def test_default_target_is_riscv64() -> None:
    """Any defconfig without an explicit ARCH_ key defaults to riscv64."""
    # edge, qemu, embedded, fleet, vf2, k1 are all riscv64
    riscv64_defconfigs = ["edge", "qemu", "embedded", "fleet", "vf2", "k1"]
    for name in riscv64_defconfigs:
        defconfig_path = DEFCONFIGS_DIR / f"{name}.config"
        output = run_bridge(defconfig_path)
        target, _features = parse_output(output)
        assert target == "riscv64imac-unknown-none-elf", (
            f"defconfig={name}: expected riscv64 target; got '{target}'"
        )


# ---------------------------------------------------------------------------
# Wave 11: application domain, robot type, threat model, driver switches
# ---------------------------------------------------------------------------

def _expand(lines: list[str], tmp_dir: Path, name: str = "w11.config") -> list[str]:
    """olddefconfig a synthetic .config in tmp_dir; return its lines."""
    cfg = tmp_dir / name
    cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")
    env = dict(os.environ, KCONFIG_CONFIG=str(cfg))
    result = subprocess.run(
        [sys.executable, "-m", "olddefconfig"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, f"olddefconfig failed on {lines}:\n{result.stderr}"
    return cfg.read_text(encoding="utf-8").splitlines()


def test_domain_defaults_to_generic_and_robot_type_is_wired() -> None:
    """Generic is the default domain; ROBOT_TYPE_ID follows the robot type only
    in the Robot domain (a hidden choice keeps no user value), and is 0 (the
    wheeled starting type every image had before) everywhere else."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        out = _expand([], t)
        assert "CONFIG_DOMAIN_GENERIC=y" in out, "Generic is not the default domain"
        assert "CONFIG_ROBOT_TYPE_ID=0" in out, "Generic must start the envelope as wheeled"
        assert not any("CONFIG_MULTISTREAM_SCHED_PRIORITY" in l for l in out), (
            "the brain-link option is shown outside the Robot domain"
        )
        out = _expand(["CONFIG_DOMAIN_ROBOT=y", "CONFIG_ROBOT_DRONE=y"], t)
        assert "CONFIG_ROBOT_TYPE_ID=1" in out, "Robot + Drone must give ROBOT_TYPE_ID=1"
        out = _expand(["CONFIG_DOMAIN_ROBOT=y"], t)
        assert "CONFIG_ROBOT_NONE=y" in out and "CONFIG_ROBOT_TYPE_ID=0" in out, (
            "Robot domain must default to robot type None, ROBOT_TYPE_ID=0"
        )
        out = _expand(["CONFIG_ROBOT_DRONE=y"], t)
        assert "CONFIG_ROBOT_TYPE_ID=0" in out, (
            "a robot type set outside the Robot domain must not reach the build"
        )


def test_threat_profile_implies_never_forces() -> None:
    """The physical-access profile turns CONSOLE_LOCKDOWN on by default, a
    hand-set n still wins, and the base profile changes no default."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        base = _expand([], t, "a.config")
        assert "CONFIG_THREAT_RING3_IMAGE=y" in base
        assert "# CONFIG_CONSOLE_LOCKDOWN is not set" in base
        assert "CONFIG_MITIGATION_SPECTRE_V1_INDEX=y" in base
        phys = _expand(["CONFIG_DOMAIN_ROBOT=y", "CONFIG_THREAT_PHYSICAL_ACCESS=y"], t, "b.config")
        for sym in ("CONSOLE_LOCKDOWN", "SECURE_BOOT_ENFORCED", "OTA_SIG_MANDATORY",
                    "LINK_AUTH_ENFORCED", "MITIGATION_SPECTRE_V1_INDEX"):
            assert f"CONFIG_{sym}=y" in phys, f"physical-access profile did not imply {sym}"
        # The brain-link switch exists only in the Robot domain (wave 11).
        gen = _expand(["CONFIG_THREAT_PHYSICAL_ACCESS=y"], t, "g.config")
        assert not any(l.startswith("CONFIG_LINK_AUTH_ENFORCED") for l in gen), (
            "LINK_AUTH_ENFORCED reached a Generic image, which has no brain link"
        )
        off = _expand(["CONFIG_THREAT_PHYSICAL_ACCESS=y",
                       "# CONFIG_CONSOLE_LOCKDOWN is not set"], t, "c.config")
        assert "# CONFIG_CONSOLE_LOCKDOWN is not set" in off, (
            "a threat profile forced a mitigation the user turned off"
        )


def test_driver_switches_follow_their_board() -> None:
    """DRV_PCI / DRV_DISPLAY_* reach --features only on the board they are for."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _expand(["CONFIG_DRV_PCI=y", "CONFIG_DRV_DISPLAY_RAMFB=y"], t, "q.config")
        _t, feats = parse_output(run_bridge(t / "q.config"))
        assert "pci" in feats and "ramfb" in feats, f"QEMU: got {feats}"
        _expand(["CONFIG_BOARD_VF2=y", "CONFIG_DRV_DISPLAY_HDMI=y", "CONFIG_DRV_PCI=y"],
                t, "v.config")
        _t, feats = parse_output(run_bridge(t / "v.config"))
        assert "hdmi" in feats and "pci" not in feats, f"VF2: got {feats}"
        _expand(["CONFIG_DRV_DISPLAY_HDMI=y"], t, "h.config")
        _t, feats = parse_output(run_bridge(t / "h.config"))
        assert "hdmi" not in feats, f"hdmi emitted on QEMU: {feats}"


def test_no_defconfig_enables_unimplemented_options() -> None:
    """No shipped defconfig turns on a Linux-compatibility option (they fail
    the build in crates/core/limits/build.rs until their code exists)."""
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        for d in sorted(DEFCONFIGS_DIR.glob("*.config")):
            cfg = Path(td) / d.name
            shutil.copyfile(d, cfg)
            out = _expand(cfg.read_text(encoding="utf-8").splitlines(), Path(td), d.name)
            on = [l for l in out if (l.startswith("CONFIG_LX_") or l.startswith("CONFIG_LINUX_DRIVERS")
                                     or l.startswith("CONFIG_USERSPACE_GPL")) and l.endswith("=y")]
            assert not on, f"{d.name} enables {on}"


def test_lx_server_skeleton_reaches_the_build() -> None:
    """RFC-0053 L0/L0b: LINUX_DRIVERS + LX_SERVER_SKELETON emits `lx-server`
    (the module loader and the empty server); the skeleton cannot be chosen
    without LINUX_DRIVERS (Kconfig `if`), and neither alone emits anything."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _expand(["CONFIG_LINUX_DRIVERS=y", "CONFIG_LX_SERVER_SKELETON=y"], t, "lx.config")
        _t, feats = parse_output(run_bridge(t / "lx.config"))
        assert "lx-server" in feats, f"LINUX_DRIVERS+LX_SERVER_SKELETON: got {feats}"
        out = _expand(["CONFIG_LX_SERVER_SKELETON=y"], t, "sk.config")
        assert "CONFIG_LX_SERVER_SKELETON=y" not in out, "the skeleton survived without LINUX_DRIVERS"
        _t, feats = parse_output(run_bridge(t / "sk.config"))
        assert "lx-server" not in feats, f"skeleton without LINUX_DRIVERS emitted {feats}"
        _expand(["CONFIG_LINUX_DRIVERS=y"], t, "ld.config")
        _t, feats = parse_output(run_bridge(t / "ld.config"))
        assert "lx-server" not in feats, f"LINUX_DRIVERS alone emitted {feats}"


def _isa(cfg: Path, *flags: str) -> str:
    script = TOOLS_DIR / "kconfig_to_cargo.py"
    r = subprocess.run([sys.executable, str(script), *flags, str(cfg)],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


def test_isa_level_and_require_reach_the_codegen() -> None:
    """config/Kconfig.arch's hardware-support model: the level and every
    `require` extension become target features (kernel and user images),
    `probe` and `n` never do, the soft-float aarch64 kernel never gets a
    feature that needs the SIMD registers, and the per-board defaults
    (QEMU: today's flags; K1: Zba/Zbb/Zbs; Raspberry Pi 5: Armv8.2 + LSE,
    no PAuth/BTI/MTE/SVE) come out of the defconfigs."""
    import tempfile

    simd = {"rdm", "dotprod", "fp16", "jsconv", "fcma", "frintts", "aes", "sha2", "sve", "neon"}
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _expand(["CONFIG_ARCH_RISCV64=y"], t, "rv.config")
        assert _isa(t / "rv.config", "--rustflags") == "-C target-feature=+zaamo,+zalrsc"
        assert _isa(t / "rv.config", "--rustflags", "--skip-base") == ""
        _expand(["CONFIG_ARCH_RISCV64=y", "CONFIG_RV_ZBB_REQUIRE=y", "CONFIG_RV_ZICBOZ_REQUIRE=y"], t, "rvb.config")
        assert _isa(t / "rvb.config", "--rustflags", "--skip-base") == "-C target-feature=+zbb"
        assert "require=zaamo,zalrsc,zbb" in _isa(t / "rvb.config", "--target-features")
        _expand((DEFCONFIGS_DIR / "k1.config").read_text().splitlines(), t, "k1.config")
        assert _isa(t / "k1.config", "--rustflags").endswith("+zba,+zbb,+zbs")
        _expand((DEFCONFIGS_DIR / "vf2.config").read_text().splitlines(), t, "vf2.config")
        assert "zb" not in _isa(t / "vf2.config", "--rustflags")
        _expand(["CONFIG_ARCH_AARCH64=y"], t, "a.config")
        assert _isa(t / "a.config", "--rustflags") == "" and _isa(t / "a.config", "--user-rustflags") == ""
        rpi = [l for l in (DEFCONFIGS_DIR / "qemu-aarch64.config").read_text().splitlines()
               if "BOARD_" not in l] + ["CONFIG_BOARD_RPI5=y"]
        out = _expand(rpi, t, "rpi5.config")
        assert "CONFIG_AARCH64_LEVEL_8_2=y" in out and "CONFIG_A64_LSE_REQUIRE=y" in out
        for ext in ("PAUTH", "BTI", "MTE", "SVE"):
            assert f"CONFIG_A64_{ext}_NEVER=y" in out, ext
        k = _isa(t / "rpi5.config", "--rustflags").split("=", 1)[1].replace("+", "").split(",")
        u = _isa(t / "rpi5.config", "--user-rustflags").split("=", 1)[1].replace("+", "").split(",")
        assert "lse" in k and "dpb" in k and not {"paca", "bti", "mte", "rcpc"} & set(k), k
        assert "rdm" in u and not simd & set(k), (k, u)
        _expand(["CONFIG_ARCH_AARCH64=y", "CONFIG_AARCH64_LEVEL_8_5=y", "CONFIG_A64_SHA2_REQUIRE=y"], t, "a85.config")
        k = _isa(t / "a85.config", "--rustflags").split("=", 1)[1].replace("+", "").split(",")
        u = _isa(t / "a85.config", "--user-rustflags").split("=", 1)[1].replace("+", "").split(",")
        assert {"lse", "rcpc", "paca", "bti"} <= set(k) and not simd & set(k), k
        assert {"sha2", "dotprod", "frintts"} <= set(u), u
        assert "control=lse,rcpc" in _isa(t / "a85.config", "--target-features")


def test_page_size_reaches_the_build() -> None:
    """config/Kconfig.arch's aarch64 granule choice emits `page-16k`/`page-64k`
    and PAGE_SHIFT 14/16; 4 KiB emits neither (it is their absence), and a
    riscv64 config has no granule choice at all (PAGE_SHIFT 12, no feature)."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for gran, feat, shift in (("4K", None, "12"), ("16K", "page-16k", "14"), ("64K", "page-64k", "16")):
            name = f"a{gran}.config"
            out = _expand(["CONFIG_ARCH_AARCH64=y", f"CONFIG_AARCH64_PAGE_{gran}=y"], t, name)
            assert f"CONFIG_PAGE_SHIFT={shift}" in out, f"{gran}: PAGE_SHIFT not {shift}"
            _t, feats = parse_output(run_bridge(t / name))
            pages = [f for f in feats if f.startswith("page-")]
            assert pages == ([feat] if feat else []), f"{gran}: got {pages}"
        out = _expand(["CONFIG_AARCH64_PAGE_16K=y"], t, "rv.config")
        assert "CONFIG_PAGE_SHIFT=12" in out, "riscv64 must stay at a 4 KiB base page"
        _t, feats = parse_output(run_bridge(t / "rv.config"))
        assert not [f for f in feats if f.startswith("page-")], f"riscv64 emitted {feats}"


# ---------------------------------------------------------------------------
# Application domains (wave 11, DOMAIN)
# ---------------------------------------------------------------------------

def _kernel_default_features() -> list[str]:
    """kernel/Cargo.toml's `[features] default`, read independently of the
    bridge (which reads it too) so a bug in one is not mirrored in the other."""
    lines = KERNEL_CARGO_TOML.read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip().startswith("default = ["))
    text = ""
    for l in lines[start:]:
        text += l.split("#", 1)[0]
        if "]" in l.split("#", 1)[0]:
            break
    return [t.strip().strip('"') for t in text.split("[", 1)[1].split("]", 1)[0].split(",") if t.strip()]


def _bridge_args(cfg: Path) -> tuple[bool, list[str]]:
    out = run_bridge(cfg)
    _t, feats = parse_output(out)
    return "--no-default-features" in out.split(), feats


PROFILE_DEFCONFIGS = ("edge", "embedded", "fleet")


def test_profile_defconfigs_generic_robot_variants_robot() -> None:
    """Owner decision (wave 11): the profile defconfigs (edge, embedded,
    fleet) are Generic; each has a robot-<profile> twin that selects
    DOMAIN_ROBOT and differs from it in the domain lines only. Every other
    shipped defconfig (boards, experimental) is a robot image, so the gate's
    rows build the image they always built."""
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        expanded = {}
        for d in sorted(DEFCONFIGS_DIR.glob("*.config")):
            cfg = t / d.name
            shutil.copyfile(d, cfg)
            expanded[d.stem] = _expand(cfg.read_text(encoding="utf-8").splitlines(), t, d.name)
            no_default, feats = _bridge_args(cfg)
            if d.stem in PROFILE_DEFCONFIGS:
                assert no_default and "domain-robot" not in feats, f"{d.name}: {feats}"
            else:
                assert not no_default, f"{d.name}: --no-default-features on a robot image"
                assert "domain-robot" in feats, f"{d.name}: no domain-robot in {feats}"
        for p in PROFILE_DEFCONFIGS:
            assert f"robot-{p}" in expanded, f"no robot-{p}.config"
            # Values outside the Robot menu and the brain-link switches.
            strip = lambda ls: [l for l in ls if l.startswith("CONFIG_")
                                and not any(k in l for k in ("DOMAIN_", "ROBOT_", "LINK_",
                                    "MULTISTREAM", "SAFETY_", "PID_DT", "ML_REPLY", "BEHAVIOR_"))]
            g, r = strip(expanded[p]), strip(expanded[f"robot-{p}"])
            diff = [l for l in r if l not in g] + [l for l in g if l not in r]
            assert not diff, f"robot-{p} differs from {p} beyond the domain: {diff}"


def test_generic_drops_only_the_domain_feature() -> None:
    """`make config` from scratch is Generic: the bridge turns the kernel's
    defaults off and adds every one of them back except `domain-robot`."""
    import tempfile

    defaults = _kernel_default_features()
    assert "domain-robot" in defaults, "domain-robot left the kernel's default list"
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        out = _expand([], t, "g.config")
        assert "CONFIG_DOMAIN_GENERIC=y" in out
        no_default, feats = _bridge_args(t / "g.config")
        assert no_default, "a Generic .config must build without the cargo defaults"
        assert "domain-robot" not in feats, f"Generic emitted domain-robot: {feats}"
        for f in defaults:
            if f != "domain-robot":
                assert f in feats, f"Generic lost the default feature {f}: {feats}"
        # The other non-robot domains build the same way.
        for dom in ("IOT_HMI", "GATEWAY", "INDUSTRIAL", "MICROKERNEL"):
            _expand([f"CONFIG_DOMAIN_{dom}=y"], t, f"{dom}.config")
            no_default, feats = _bridge_args(t / f"{dom}.config")
            assert no_default and "domain-robot" not in feats, f"{dom}: {feats}"
        _expand(["CONFIG_DOMAIN_ROBOT=y"], t, "r.config")
        no_default, feats = _bridge_args(t / "r.config")
        assert not no_default and "domain-robot" in feats, f"Robot: {feats}"


def test_iot_hmi_implies_display_and_camera() -> None:
    """IoT-HMI turns on the board's display and the camera by default; each
    can still be turned off, and another domain turns neither on."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        q = _expand(["CONFIG_DOMAIN_IOT_HMI=y"], t, "q.config")
        assert "CONFIG_DRV_DISPLAY_RAMFB=y" in q and "CONFIG_DRV_CAMERA=y" in q, "QEMU riscv64"
        _nd, feats = _bridge_args(t / "q.config")
        assert "ramfb" in feats and "camera" in feats, f"QEMU riscv64: {feats}"
        v = _expand(["CONFIG_DOMAIN_IOT_HMI=y", "CONFIG_BOARD_VF2=y"], t, "v.config")
        assert "CONFIG_DRV_DISPLAY_HDMI=y" in v and "CONFIG_DRV_CAMERA=y" in v, "VF2"
        a = _expand(["CONFIG_DOMAIN_IOT_HMI=y", "CONFIG_ARCH_AARCH64=y"], t, "a.config")
        assert "CONFIG_DRV_CAMERA=y" in a, "aarch64 QEMU: camera"
        assert not any(l.startswith("CONFIG_DRV_DISPLAY_RAMFB=y") for l in a), (
            "ramfb implied on aarch64, where it does not build")
        off = _expand(["CONFIG_DOMAIN_IOT_HMI=y", "# CONFIG_DRV_CAMERA is not set"], t, "o.config")
        assert "# CONFIG_DRV_CAMERA is not set" in off, "imply forced the camera on"
        g = _expand([], t, "g.config")
        assert "# CONFIG_DRV_CAMERA is not set" in g and "# CONFIG_DRV_DISPLAY_RAMFB is not set" in g


def _value(lines: list[str], sym: str) -> Optional[str]:
    for l in lines:
        if l.startswith(f"CONFIG_{sym}="):
            return l.split("=", 1)[1]
    return None


GATEWAY_EDGE = {"TCP_MAX_CONNS": "64", "TCP_BUF_SIZE": "16384", "MAX_SOCKETS": "128",
                "ARP_CACHE_SIZE": "64", "ARP_PENDING_SIZE": "16", "DNS_CACHE_SIZE": "16",
                "UDP_RX_SLOTS": "16"}
EDGE = {"TCP_MAX_CONNS": "8", "TCP_BUF_SIZE": "131072", "MAX_SOCKETS": "16",
        "ARP_CACHE_SIZE": "16", "ARP_PENDING_SIZE": "8", "DNS_CACHE_SIZE": "4",
        "UDP_RX_SLOTS": "4"}


def test_gateway_raises_network_defaults_on_edge() -> None:
    """Gateway on the Edge profile starts with the larger network tables;
    a hand-set value wins; Fleet keeps its own; other domains keep Edge's."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        g = _expand(["CONFIG_DOMAIN_GATEWAY=y"], t, "g.config")
        for sym, val in GATEWAY_EDGE.items():
            assert _value(g, sym) == val, f"Gateway/Edge {sym}={_value(g, sym)}, want {val}"
        e = _expand([], t, "e.config")
        for sym, val in EDGE.items():
            assert _value(e, sym) == val, f"Generic/Edge {sym}={_value(e, sym)}, want {val}"
        h = _expand(["CONFIG_DOMAIN_GATEWAY=y", "CONFIG_TCP_MAX_CONNS=12"], t, "h.config")
        assert _value(h, "TCP_MAX_CONNS") == "12", "a hand-set TCP_MAX_CONNS lost to the domain"
        f = _expand(["CONFIG_DOMAIN_GATEWAY=y", "CONFIG_PROFILE_FLEET=y"], t, "f.config")
        assert _value(f, "TCP_MAX_CONNS") == "1024", "Gateway overrode the Fleet profile"
        # The limits crate's own checks accept the Gateway values.
        assert int(GATEWAY_EDGE["MAX_SOCKETS"]) >= int(GATEWAY_EDGE["TCP_MAX_CONNS"]) + 4
        n = int(GATEWAY_EDGE["UDP_RX_SLOTS"])
        assert n & (n - 1) == 0


def test_industrial_starts_with_the_physical_access_threat_model() -> None:
    """Industrial defaults the threat model to physical access (and so its
    implied mitigations); the user can still pick another profile."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        i = _expand(["CONFIG_DOMAIN_INDUSTRIAL=y"], t, "i.config")
        assert "CONFIG_THREAT_PHYSICAL_ACCESS=y" in i
        for sym in ("CONSOLE_LOCKDOWN", "SECURE_BOOT_ENFORCED", "OTA_SIG_MANDATORY"):
            assert f"CONFIG_{sym}=y" in i, f"Industrial did not get {sym}"
        _nd, feats = _bridge_args(t / "i.config")
        assert "secure-boot-enforced" in feats, f"Industrial: {feats}"
        back = _expand(["CONFIG_DOMAIN_INDUSTRIAL=y", "CONFIG_THREAT_RING3_IMAGE=y"], t, "b.config")
        assert "CONFIG_THREAT_RING3_IMAGE=y" in back, "the domain forced the threat model"
        g = _expand([], t, "g.config")
        assert "CONFIG_THREAT_RING3_IMAGE=y" in g


def test_microkernel_implies_ring3_placement() -> None:
    """Wave 11 (DRVPLACE): Microkernel implies DRV_RING3_DEFAULT, which every
    driver placement choice follows, and changes nothing else; the imply can
    be turned off and each placement set by hand."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        strip = lambda ls: [l for l in ls if "DOMAIN_" not in l]
        g = strip(_expand([], t, "g.config"))
        m = strip(_expand(["CONFIG_DOMAIN_MICROKERNEL=y"], t, "m.config"))
        assert "CONFIG_DRV_RING3_DEFAULT=y" in m and "CONFIG_DRV_INA219_PLACEMENT_RING3=y" in m, m
        assert "# CONFIG_DRV_RING3_DEFAULT is not set" in g, "Generic must not start in ring 3"
        diff = [l for l in m if l not in g] + [l for l in g if l not in m]
        assert sorted(diff) == sorted(["CONFIG_DRV_RING3_DEFAULT=y",
                                       "# CONFIG_DRV_RING3_DEFAULT is not set"]), diff
        off = _expand(["CONFIG_DOMAIN_MICROKERNEL=y", "# CONFIG_DRV_RING3_DEFAULT is not set"],
                      t, "o.config")
        assert "# CONFIG_DRV_RING3_DEFAULT is not set" in off, "the imply forced DRV_RING3_DEFAULT"
        k = _expand(["CONFIG_DOMAIN_MICROKERNEL=y", "CONFIG_DRV_INA219_PLACEMENT_KERNEL=y"],
                    t, "k.config")
        assert "CONFIG_DRV_INA219_PLACEMENT_KERNEL=y" in k, "a hand-set placement lost to the domain"
        assert "CONFIG_DRV_BUZZER_PLACEMENT_RING3=y" in m, "the buzzer did not follow DRV_RING3_DEFAULT"


def test_driver_placement_reaches_the_build() -> None:
    """DRV_INA219_PLACEMENT: `kernel` is the kernel feature `ina219-kernel`,
    from the full bridge and from `--domain-only` (`make build`); `ring3`
    (the default) is no feature, as a build naming its features by hand."""
    import tempfile

    script = TOOLS_DIR / "kconfig_to_cargo.py"
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        d = _expand([], t, "d.config")
        assert "CONFIG_DRV_INA219_PLACEMENT_RING3=y" in d, "the default placement is not ring3"
        _nd, feats = _bridge_args(t / "d.config")
        assert "ina219-kernel" not in feats, feats
        for dom in ([], ["CONFIG_DOMAIN_ROBOT=y"]):
            _expand(dom + ["CONFIG_DRV_INA219_PLACEMENT_KERNEL=y"], t, "k.config")
            _nd, feats = _bridge_args(t / "k.config")
            assert "ina219-kernel" in feats, (dom, feats)
            out = subprocess.run([sys.executable, str(script), "--domain-only", str(t / "k.config")],
                                 capture_output=True, text=True, check=True).stdout
            assert "ina219-kernel" in out, (dom, out)
        # Wave 12: the buzzer's choice, the same way.
        assert "CONFIG_DRV_BUZZER_PLACEMENT_RING3=y" in d, "the buzzer's default is not ring3"
        assert "buzzer-kernel" not in feats or "CONFIG_DRV_BUZZER_PLACEMENT_KERNEL=y" in d, feats
        _expand(["CONFIG_DRV_BUZZER_PLACEMENT_KERNEL=y"], t, "b.config")
        _nd, feats = _bridge_args(t / "b.config")
        assert "buzzer-kernel" in feats and "ina219-kernel" not in feats, feats


def test_a_safety_read_driver_is_never_placed_in_ring3() -> None:
    """A .config that places a driver a safety decision reads in ring 3 is
    refused (exit 1, nothing on stdout), not built."""
    import tempfile

    script = TOOLS_DIR / "kconfig_to_cargo.py"
    with tempfile.TemporaryDirectory() as td:
        c = Path(td) / "bad.config"
        c.write_text("CONFIG_ARCH_RISCV64=y\nCONFIG_DRV_ADS1115_PLACEMENT_RING3=y\n")
        r = subprocess.run([sys.executable, str(script), str(c)], capture_output=True, text=True)
        assert r.returncode == 1 and r.stdout == "" and "ADS1115" in r.stderr, r
        c.write_text("CONFIG_ARCH_RISCV64=y\nCONFIG_DRV_INA219_PLACEMENT_RING3=y\n")
        r = subprocess.run([sys.executable, str(script), str(c)], capture_output=True, text=True)
        assert r.returncode == 0, r


def test_domain_only_for_hand_written_targets() -> None:
    """`--domain-only` (used by `make build`, which names `--features qemu`
    itself) prints only the domain's effect: the defaults without
    `domain-robot` outside DOMAIN_ROBOT, nothing for it."""
    import tempfile

    script = TOOLS_DIR / "kconfig_to_cargo.py"
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _expand([], t, "g.config")
        _expand(["CONFIG_DOMAIN_ROBOT=y"], t, "r.config")
        run = lambda c: subprocess.run([sys.executable, str(script), "--domain-only", str(c)],
                                       capture_output=True, text=True, check=True).stdout.split()
        g = run(t / "g.config")
        assert g[:2] == ["--no-default-features", "--features"], g
        assert "domain-robot" not in g[2].split(",") and "qemu" not in g[2].split(","), g
        assert "--target" not in g, g
        assert run(t / "r.config") == [], "a Robot .config must add nothing"


# ---------------------------------------------------------------------------
# Simple self-runner (also works with pytest)
# ---------------------------------------------------------------------------

def _run_all_tests() -> int:
    """Run all test_* functions and report results."""
    tests = [
        test_kernel_features_parseable,
        test_no_phantom_features,
        test_all_emitted_features_are_valid,
        test_target_triples_are_valid,
        test_expected_features_present_and_absent,
        test_missing_dot_config_emits_nothing,
        test_edge_no_ml_absent,
        test_aarch64_target_selection,
        test_no_config_emits_small_mem,
        test_embedded_ram_size_comes_through,
        test_fleet_ram_size_holds_the_heap,
        test_default_target_is_riscv64,
        test_domain_defaults_to_generic_and_robot_type_is_wired,
        test_threat_profile_implies_never_forces,
        test_driver_switches_follow_their_board,
        test_no_defconfig_enables_unimplemented_options,
        test_page_size_reaches_the_build,
        test_isa_level_and_require_reach_the_codegen,
        test_lx_server_skeleton_reaches_the_build,
        test_profile_defconfigs_generic_robot_variants_robot,
        test_generic_drops_only_the_domain_feature,
        test_iot_hmi_implies_display_and_camera,
        test_gateway_raises_network_defaults_on_edge,
        test_industrial_starts_with_the_physical_access_threat_model,
        test_microkernel_implies_ring3_placement,
        test_driver_placement_reaches_the_build,
        test_a_safety_read_driver_is_never_placed_in_ring3,
        test_domain_only_for_hand_written_targets,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            print(f"  PASS  {test_fn.__name__}")
            passed += 1
        except AssertionError as exc:
            print(f"  FAIL  {test_fn.__name__}: {exc}")
            failed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR {test_fn.__name__}: {type(exc).__name__}: {exc}")
            failed += 1

    print(f"\n{passed + failed} tests: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(_run_all_tests())
