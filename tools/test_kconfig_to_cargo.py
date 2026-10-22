#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_kconfig_to_cargo.py — bridge-script unit tests.

Verifies that tools/kconfig_to_cargo.py:
  1. Emits a valid --target triple for every defconfig.
  2. Emits ONLY cargo features that exist in kernel/Cargo.toml [features] OR
     in a named sub-crate as a "crate/feat" token.
  3. Does NOT emit phantom features (brain-l1, brain-l2, brain-l3, etc.).
  4. Emits the correct target triple per architecture.

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
        {"vf2", "k1", "no-ml"},  # must not appear
    ),
    # qemu — identical to edge (explicit alias)
    (
        "qemu",
        "riscv64imac-unknown-none-elf",
        set(),
        {"vf2", "k1", "no-ml"},
    ),
    # vf2 — must emit vf2 feature
    (
        "vf2",
        "riscv64imac-unknown-none-elf",
        {"vf2", "soc", "soc-jh7110"},       # SOC_FRAMEWORKS / SOC_JH7110, the board's frameworks
        {"k1", "no-ml", "soc-k1"},
    ),
    # k1 — must emit k1 feature, and the K1 providers of the SoC frameworks
    (
        "k1",
        "riscv64imac-unknown-none-elf",
        {"k1", "soc", "soc-k1"},            # SOC_FRAMEWORKS / SOC_K1, the board's frameworks
        {"vf2", "no-ml", "soc-jh7110"},
    ),
    # embedded — no cargo feature at all: its sizing is constants only, and
    # small-mem (PMM capped at 128 pages) must not come back
    (
        "embedded",
        "riscv64imac-unknown-none-elf",
        set(),
        {"azos_mm/small-mem", "vf2", "k1", "qemu", "no-ml"},
    ),
    # fleet — all defaults, large caps via constants (no cargo features)
    (
        "fleet",
        "riscv64imac-unknown-none-elf",
        set(),
        {"vf2", "k1", "no-ml"},
    ),
    # qemu-aarch64 — must emit aarch64 target
    (
        "qemu-aarch64",
        "aarch64-unknown-none-softfloat",
        set(),
        {"vf2", "k1", "no-ml", "soc", "soc-jh7110", "soc-k1"},  # no aarch64 board enables the SoC frameworks
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
    for expected in ("vf2", "k1", "qemu", "no-ml",
                     "rvv", "dhcp-smoke",
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
    PMM manages all the RAM the firmware reports on every profile now. The embedded profile
    is checked alone and on each board, since the old row keyed on the profile
    and ignored the board.
    """
    import tempfile

    profiles = ["CONFIG_HWCLASS_EMBEDDED=y", "CONFIG_HWCLASS_SBC=y", "CONFIG_HWCLASS_SERVER=y"]
    boards = [None, "CONFIG_BOARD_GENERIC=y", "CONFIG_BOARD_QEMU=y",
              "CONFIG_BOARD_VF2=y", "CONFIG_BOARD_K1=y"]
    with tempfile.TemporaryDirectory() as td:
        for profile in profiles:
            for board in boards:
                lines = [profile] + ([board] if board else [])
                features = _bridge_features_for(lines, Path(td))
                offending = [f for f in features if "small-mem" in f]
                assert not offending, (
                    f"config {lines}: emitted {offending}; the PMM must manage all the "
                    f"RAM, not be capped by small-mem"
                )


def test_embedded_ram_size_comes_through() -> None:
    """config/defconfigs/embedded.config expands to RAM_SIZE=64 and the embedded profile.

    RAM_SIZE is the RAM the board is expected to have (the build checks the heap
    against it). The generic board's default is 256 (config/Kconfig.platform), so the value has to
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
        assert "CONFIG_HWCLASS_EMBEDDED=y" in expanded, "embedded profile lost in expansion"
        ram = [l for l in expanded if l.startswith("CONFIG_RAM_SIZE=")]
        assert ram == ["CONFIG_RAM_SIZE=64"], (
            f"expanded embedded config carries {ram}, expected ['CONFIG_RAM_SIZE=64']"
        )
        _target, features = parse_output(run_bridge(cfg))
        # The embedded profile is Generic (wave 11, owner decision): no board
        # feature, the always-on base features and no robot one. A small board
        # starts only the drivers its topology names: no virtio-input and no
        # virtio-snd. A
        # board is a release build: secure boot is enforced by default.
        want = sorted([f for f in ALWAYS_BASE if f not in ("virtio-input", "virtio-snd", "rtc")]
                      + ["secure-boot-enforced"])
        assert sorted(features) == want, (
            f"expanded embedded config emitted features {features}; expected {want}"
        )


def test_fleet_ram_size_holds_the_heap() -> None:
    """config/defconfigs/fleet.config expands to RAM_SIZE=1024.

    The limits build refuses a heap that is not smaller than RAM_SIZE, and the
    fleet heap (256 MiB) is taken from RAM after a ~134 MiB image. At the generic board's default of 256 the
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
        assert "CONFIG_HWCLASS_SERVER=y" in expanded, "fleet profile lost in expansion"
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
        assert "CONFIG_USE_GENERIC=y" in out, "Generic is not the default domain"
        assert "CONFIG_ROBOT_TYPE_ID=0" in out, "Generic must start the envelope as wheeled"
        assert not any("CONFIG_MULTISTREAM_SCHED_PRIORITY" in l for l in out), (
            "the brain-link option is shown outside the Robot domain"
        )
        out = _expand(["CONFIG_PRESET_ROBOT=y", "CONFIG_ROBOT_DRONE=y"], t)
        assert "CONFIG_ROBOT_TYPE_ID=1" in out, "Robot + Drone must give ROBOT_TYPE_ID=1"
        out = _expand(["CONFIG_PRESET_ROBOT=y"], t)
        assert "CONFIG_ROBOT_NONE=y" in out and "CONFIG_ROBOT_TYPE_ID=0" in out, (
            "Robot domain must default to robot type None, ROBOT_TYPE_ID=0"
        )
        out = _expand(["CONFIG_ROBOT_DRONE=y"], t)
        assert "CONFIG_ROBOT_TYPE_ID=0" in out, (
            "a robot type set outside the Robot domain must not reach the build"
        )


def test_threat_profile_implies_never_forces() -> None:
    """The physical-access security postures (separation-static and
    confidential: the threat model is the SECURITY axis) turn CONSOLE_LOCKDOWN
    on by default, a hand-set n still wins, and the base posture changes no
    default."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        base = _expand([], t, "a.config")
        assert "CONFIG_SECURITY_GENERAL=y" in base
        assert "# CONFIG_CONSOLE_LOCKDOWN is not set" in base
        assert "CONFIG_MITIGATION_SPECTRE_V1_INDEX=y" in base
        for posture in ("SEPARATION_STATIC", "CONFIDENTIAL"):
            phys = _expand(["CONFIG_PRESET_ROBOT=y", f"CONFIG_SECURITY_{posture}=y"], t, "b.config")
            for sym in ("CONSOLE_LOCKDOWN", "SECURE_BOOT_ENFORCED", "OTA_SIG_MANDATORY",
                        "LINK_PROVISIONING_ENFORCED", "MITIGATION_SPECTRE_V1_INDEX"):
                assert f"CONFIG_{sym}=y" in phys, f"SECURITY_{posture} did not imply {sym}"
        hard = _expand(["CONFIG_PRESET_ROBOT=y", "CONFIG_SECURITY_HARDENED=y"], t, "h.config")
        assert "# CONFIG_CONSOLE_LOCKDOWN is not set" in hard, "hardened implied the physical-access set"
        # The brain-link switch exists only in the Robot domain (wave 11).
        gen = _expand(["CONFIG_SECURITY_SEPARATION_STATIC=y"], t, "g.config")
        assert not any(l.startswith("CONFIG_LINK_PROVISIONING_ENFORCED") for l in gen), (
            "LINK_PROVISIONING_ENFORCED reached a Generic image, which has no brain link"
        )
        off = _expand(["CONFIG_SECURITY_SEPARATION_STATIC=y",
                       "# CONFIG_CONSOLE_LOCKDOWN is not set"], t, "c.config")
        assert "# CONFIG_CONSOLE_LOCKDOWN is not set" in off, (
            "a security posture forced a mitigation the user turned off"
        )


def test_driver_switches_follow_their_board() -> None:
    """DRV_PCI / DRV_DISPLAY_* reach --features only on the boards they are for."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _expand(["CONFIG_DRV_PCI=y", "CONFIG_DRV_DISPLAY_RAMFB=y"], t, "q.config")
        _t, feats = parse_output(run_bridge(t / "q.config"))
        assert "pci" in feats and "ramfb" in feats, f"QEMU: got {feats}"
        _expand(["CONFIG_BOARD_VF2=y", "CONFIG_DRV_DISPLAY_HDMI=y", "CONFIG_DRV_PCI=y"],
                t, "v.config")
        _t, feats = parse_output(run_bridge(t / "v.config"))
        # The VisionFive 2 is a PCI board (its PLDA root port is brought up
        # by PCI_SOC_HOST); a board without a host-bridge flow is not.
        assert "hdmi" in feats and "pci" in feats, f"VF2: got {feats}"
        _expand(["CONFIG_BOARD_K1=y", "CONFIG_DRV_PCI=y"], t, "k.config")
        _t, feats = parse_output(run_bridge(t / "k.config"))
        assert "pci" not in feats, f"K1: got {feats}"
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
    """LINUX_DRIVERS + LX_SERVER_SKELETON emits `lx-server`
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


BP = " -Z branch-protection=bti,pac-ret"   # aarch64 with BTI and PAuth not `n`
CF = " -Z cf-protection=branch"            # x86_64 with CET IBT not `n`
# The position-independent kernel of a KASLR policy that is not `n` (kernel only):
# the codegen half; the `-pie` link itself is kernel/build.rs's.
KASLR_PIE = " -C relocation-model=static"
# The tests below judge the codegen flags alone, so their configs pin the policy: KASLR
# probes by default on every build type (test_kaslr_links_position_independent).
NO_SLIDE = "CONFIG_KASLR_NEVER=y"
KASLR_PIE_X86 = " -C relocation-model=pie -Z relax-elf-relocations=yes"


def _pie(isa: str) -> str:
    """The position-independent kernel link of `isa` (`pie` code on x86_64)."""
    return KASLR_PIE_X86 if isa == "X86_64" else KASLR_PIE


def _tf(flags: str) -> list[str]:
    """The `-C target-feature=+a,+b` list inside a flag string."""
    tok = next(w for w in flags.split() if w.startswith("target-feature="))
    return tok.split("=", 1)[1].replace("+", "").split(",")


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
        _expand(["CONFIG_ARCH_RISCV64=y", NO_SLIDE], t, "rv.config")
        assert _isa(t / "rv.config", "--rustflags") == "-C target-feature=+zaamo,+zalrsc"
        assert _isa(t / "rv.config", "--rustflags", "--skip-base") == ""
        _expand(["CONFIG_ARCH_RISCV64=y", NO_SLIDE, "CONFIG_RV_ZBB_REQUIRE=y", "CONFIG_RV_ZICBOZ_REQUIRE=y"], t, "rvb.config")
        assert _isa(t / "rvb.config", "--rustflags", "--skip-base") == "-C target-feature=+zbb"
        assert "require=zaamo,zalrsc,zbb" in _isa(t / "rvb.config", "--target-features")
        _expand((DEFCONFIGS_DIR / "k1.config").read_text().splitlines(), t, "k1.config")
        # A product config (not BUILD_TYPE_DEV) slides its kernel: the PIE link
        # flags follow the target features (test_kaslr_links_position_independent).
        assert _isa(t / "k1.config", "--rustflags").replace(KASLR_PIE, "").endswith("+zba,+zbb,+zbs")
        _expand((DEFCONFIGS_DIR / "vf2.config").read_text().splitlines(), t, "vf2.config")
        assert "zb" not in _isa(t / "vf2.config", "--rustflags")
        _expand(["CONFIG_ARCH_AARCH64=y", NO_SLIDE], t, "a.config")
        # No `require`, so no target feature; BTI and PAuth are `probe`, whose
        # landing pads and signed returns are no-ops on a core without them.
        assert _isa(t / "a.config", "--rustflags") == BP.strip() == _isa(t / "a.config", "--user-rustflags")
        rpi = [l for l in (DEFCONFIGS_DIR / "qemu-aarch64.config").read_text().splitlines()
               if "BOARD_" not in l] + ["CONFIG_BOARD_RPI5=y"]
        out = _expand(rpi, t, "rpi5.config")
        assert "CONFIG_AARCH64_LEVEL_8_2=y" in out and "CONFIG_A64_LSE_REQUIRE=y" in out
        for ext in ("PAUTH", "BTI", "MTE", "SVE"):
            assert f"CONFIG_A64_{ext}_NEVER=y" in out, ext
        # PAuth and BTI are `n` there (the Cortex-A76 has neither): no pads at all.
        assert "branch-protection" not in _isa(t / "rpi5.config", "--rustflags")
        assert "branch-protection" not in _isa(t / "rpi5.config", "--user-rustflags")
        k = _tf(_isa(t / "rpi5.config", "--rustflags"))
        u = _tf(_isa(t / "rpi5.config", "--user-rustflags"))
        assert "lse" in k and "dpb" in k and not {"paca", "bti", "mte", "rcpc"} & set(k), k
        assert "rdm" in u and not simd & set(k), (k, u)
        _expand(["CONFIG_ARCH_AARCH64=y", "CONFIG_AARCH64_LEVEL_8_5=y", "CONFIG_A64_SHA2_REQUIRE=y"], t, "a85.config")
        k = _tf(_isa(t / "a85.config", "--rustflags"))
        u = _tf(_isa(t / "a85.config", "--user-rustflags"))
        assert {"lse", "rcpc", "paca", "bti"} <= set(k) and not simd & set(k), k
        assert {"sha2", "dotprod", "frintts"} <= set(u), u
        assert "control=lse,rcpc" in _isa(t / "a85.config", "--target-features")


RT = " -Z retpoline -Z retpoline-external-thunk"


def test_cfi_pads_follow_each_isas_extension_choices() -> None:
    """Hardware control-flow integrity (plan item I4): the landing pads and
    signed returns are built into the kernel AND the user images whenever the
    ISA's extension choice is not `n` (probe and require build the same code:
    the pads are no-ops on a CPU without the extension), per mode on aarch64;
    riscv64 has no CFI symbol yet (tests/host/cfi-tests covers the same rows
    through the Rust suite)."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _expand(["CONFIG_ARCH_AARCH64=y", NO_SLIDE, "CONFIG_A64_BTI_NEVER=y"], t, "a.config")
        for which in ("--rustflags", "--user-rustflags"):
            assert _isa(t / "a.config", which) == "-Z branch-protection=pac-ret", which
        _expand(["CONFIG_ARCH_X86_64=y", "CONFIG_X86_CET_IBT_NEVER=y"], t, "x.config")
        assert CF.strip() not in _isa(t / "x.config", "--rustflags")
        _expand(["CONFIG_ARCH_RISCV64=y"], t, "r.config")
        assert "zicfilp" not in _isa(t / "r.config", "--rustflags")


def test_x86_64_level_and_require_reach_the_codegen() -> None:
    """x86_64: the level is `-C target-cpu`; a `require` integer extension
    reaches the kernel and the user images, a `require` SIMD one only the
    user images (the kernel is soft-float); the QEMU defconfig is v2 with
    every other extension on `probe` but LA57 (`n`); a level forces `require` on its
    extensions and an `n` prerequisite forces `n` on its dependants."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        out = _expand((DEFCONFIGS_DIR / "qemu-x86_64.config").read_text().splitlines(), t, "q.config")
        assert "CONFIG_X86_64_LEVEL_V2=y" in out
        assert "CONFIG_X86_SSE4_2_REQUIRE=y" in out and "CONFIG_X86_POPCNT_REQUIRE=y" in out
        for ext in ("AVX2", "AVX512F", "AES", "SHA_NI", "RDSEED", "CET_SHSTK", "INVARIANT_TSC"):
            assert f"CONFIG_X86_{ext}_PROBE=y" in out, ext
        # LA57 is `n` by default since the 5-level walk is real (1732f943):
        # a probe would put every TLB miss on a 5-level walk on any CPU
        # that has it, for VA nobody here needs.
        assert "CONFIG_X86_LA57_NEVER=y" in out
        # The development defconfig slides (KASLR probe), so its flags end in the PIE link.
        assert _isa(t / "q.config", "--rustflags") == "-C target-cpu=x86-64-v2" + CF + RT + KASLR_PIE_X86
        assert _isa(t / "q.config", "--target-features").startswith("require=cmpxchg16b,lahfsahf,popcnt\n")
        _expand(["CONFIG_ARCH_X86_64=y", NO_SLIDE, "CONFIG_X86_64_LEVEL_V4=y", "CONFIG_X86_ADX_REQUIRE=y",
                 "CONFIG_X86_AES_REQUIRE=y", "CONFIG_X86_XSAVES_REQUIRE=y"], t, "v4.config")
        assert _isa(t / "v4.config", "--rustflags") == \
            "-C target-cpu=x86-64-v4 -C target-feature=+adx,+xsaves" + CF + RT
        assert _isa(t / "v4.config", "--user-rustflags") == \
            "-C target-cpu=x86-64-v4 -C target-feature=+aes,+adx,+xsaves" + CF
        tf = _isa(t / "v4.config", "--target-features")
        assert "require=cmpxchg16b,lahfsahf,popcnt,bmi1,bmi2,lzcnt,movbe,xsave,adx,xsaves" in tf, tf
        assert "aes" not in tf and "avx" not in tf, tf
        out = _expand(["CONFIG_ARCH_X86_64=y", "CONFIG_X86_64_LEVEL_V3=y", "CONFIG_X86_AVX2_NEVER=y"],
                      t, "v3.config")
        assert "CONFIG_X86_AVX2_REQUIRE=y" in out, "v3 left AVX2 at n"
        out = _expand(["CONFIG_ARCH_X86_64=y", NO_SLIDE, "CONFIG_X86_64_LEVEL_V1=y", "CONFIG_X86_XSAVE_NEVER=y",
                       "CONFIG_X86_AVX2_REQUIRE=y"], t, "v1.config")
        assert "CONFIG_X86_AVX_NEVER=y" in out and "CONFIG_X86_AVX2_NEVER=y" in out, "AVX2 without XSAVE"
        # XSAVE `n` takes XSAVES and with it CET IBT to `n`: no ENDBR64 pads.
        assert "CONFIG_X86_CET_IBT_NEVER=y" in out
        assert _isa(t / "v1.config", "--rustflags") == "-C target-cpu=x86-64" + RT
        # X86_MIT_SPECTRE_V2: the thunk is built only under probe, and only into the kernel.
        for pol, flags in (("NEVER", ""), ("REQUIRE", ""), ("PROBE", RT)):
            _expand(["CONFIG_ARCH_X86_64=y", NO_SLIDE, f"CONFIG_X86_MIT_SPECTRE_V2_{pol}=y"], t, f"m{pol}.config")
            assert _isa(t / f"m{pol}.config", "--rustflags") == "-C target-cpu=x86-64-v2" + CF + flags, pol
        assert RT not in _isa(t / "mPROBE.config", "--user-rustflags")


def test_kaslr_links_position_independent() -> None:
    """Kconfig KASLR (config/Kconfig.security): any policy but `n`, where the
    choice exists, builds the KERNEL's code for a static position-independent
    link (`pie` code on x86_64, whose `-mcmodel=kernel` absolute operands
    cannot be slid; the `-pie` link itself is kernel/build.rs's, so no build
    command line can drop it); `n` leaves the flags as they were; the choice is hidden,
    and so the flags absent, on a small riscv64 board and on the Limine image;
    user images never get them."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for isa, model in (("AARCH64", "static"), ("RISCV64", "static"), ("X86_64", "pie")):
            pie = f" -C relocation-model={model}" + (" -Z relax-elf-relocations=yes" if isa == "X86_64" else "")
            out = _expand([f"CONFIG_ARCH_{isa}=y", "CONFIG_KASLR_PROBE=y"], t, "p.config")
            assert "CONFIG_KASLR_PROBE=y" in out and "CONFIG_KASLR_AVAILABLE=y" in out, isa
            assert pie in _isa(t / "p.config", "--rustflags"), isa
            assert "relocation-model" not in _isa(t / "p.config", "--user-rustflags"), isa
            _expand([f"CONFIG_ARCH_{isa}=y", "CONFIG_KASLR_REQUIRE=y"], t, "r.config")
            assert pie in _isa(t / "r.config", "--rustflags"), isa
            _expand([f"CONFIG_ARCH_{isa}=y", "CONFIG_KASLR_NEVER=y"], t, "n.config")
            assert "relocation-model" not in _isa(t / "n.config", "--rustflags"), isa
        out = _expand(["CONFIG_ARCH_RISCV64=y", "CONFIG_HWCLASS_EMBEDDED=y", "CONFIG_KASLR_PROBE=y"], t, "e.config")
        assert "CONFIG_KASLR_AVAILABLE=y" not in out and "CONFIG_KASLR_PROBE=y" not in out
        assert "relocation-model" not in _isa(t / "e.config", "--rustflags")
        out = _expand(["CONFIG_ARCH_X86_64=y", "CONFIG_X86_BOOT_LIMINE=y", "CONFIG_KASLR_PROBE=y"], t, "l.config")
        assert "CONFIG_KASLR_AVAILABLE=y" not in out
        assert "relocation-model" not in _isa(t / "l.config", "--rustflags")
        # Defaults: probe on every build type, the development defconfigs
        # included (they slide, with exactly the flags a probe asks for);
        # require on a Hardened posture and on a certifiable build.
        for name, isa in (("qemu.config", "RISCV64"), ("qemu-aarch64.config", "AARCH64"), ("qemu-x86_64.config", "X86_64")):
            out = _expand((DEFCONFIGS_DIR / name).read_text().splitlines(), t, name)
            assert "CONFIG_KASLR_PROBE=y" in out, name
            assert _pie(isa) in _isa(t / name, "--rustflags"), name
            assert "relocation-model" not in _isa(t / name, "--user-rustflags"), name
        for isa in ("AARCH64", "RISCV64", "X86_64"):
            # A certifiable build is not offered on the QEMU board.
            for extra, want in ((["CONFIG_BUILD_TYPE_RELEASE=y"], "PROBE"), (["CONFIG_BUILD_TYPE_DEV=y"], "PROBE"),
                                (["CONFIG_BOARD_GENERIC=y", "CONFIG_BUILD_TYPE_CERTIFIABLE=y"], "REQUIRE"),
                                (["CONFIG_SECURITY_HARDENED=y"], "REQUIRE"), (["CONFIG_SECURITY_GENERAL=y"], "PROBE")):
                out = _expand([f"CONFIG_ARCH_{isa}=y", *extra], t, "d.config")
                assert f"CONFIG_KASLR_{want}=y" in out, (isa, extra)
                assert _pie(isa) in _isa(t / "d.config", "--rustflags"), (isa, extra)
        # Where the choice is hidden the default does not apply, and a posture
        # that asks for `require` does not turn it on: no flags, no policy.
        for extra in (["CONFIG_SECURITY_HARDENED=y"], []):
            out = _expand(["CONFIG_ARCH_RISCV64=y", "CONFIG_HWCLASS_EMBEDDED=y", *extra], t, "eh.config")
            assert "CONFIG_KASLR_AVAILABLE=y" not in out and "CONFIG_KASLR_REQUIRE=y" not in out, extra
            assert "relocation-model" not in _isa(t / "eh.config", "--rustflags"), extra
            out = _expand(["CONFIG_ARCH_X86_64=y", "CONFIG_X86_BOOT_LIMINE=y", *extra], t, "lh.config")
            assert "CONFIG_KASLR_AVAILABLE=y" not in out and "CONFIG_KASLR_REQUIRE=y" not in out, extra
            assert "relocation-model" not in _isa(t / "lh.config", "--rustflags"), extra


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

# The features no domain turns off: the scheduler options and the refusal
# receipts (`base` tags on symbols that default y everywhere).
ALWAYS_BASE = ("sched-o1-placement", "sched-ipc-affinity", "sched-timer-heap", "decisions-durable",
               "virtio-input", "virtio-snd", "rtc")
# Base features of every hardware class but embedded (`default n if HWCLASS_EMBEDDED`).
FULL_PROFILE_BASE = ("crashdump", "inspect", "decisions")


def _bridge_args(cfg: Path) -> list[str]:
    out = run_bridge(cfg)
    assert "--no-default-features" not in out.split(), out  # the kernel has no `default`
    _t, feats = parse_output(out)
    return feats


PROFILE_DEFCONFIGS = ("edge", "embedded", "fleet")
# Defconfigs of another kernel: micro.config configures AzOS-micro (`make
# micro`), which no main-kernel feature set is built from, so it is neither a
# profile nor a robot image.
OTHER_KERNEL_DEFCONFIGS = ("micro",)
# The kernels that run inside the hypervisor guests (`make azos-guest`) are the
# general preset on purpose: a guest needs no robot domain.
GUEST_KERNEL_DEFCONFIGS = ("qemu-guest", "qemu-aarch64-guest")

# The base features a non-robot .config builds without: the domain feature
# and the robot subsystems it owns (`base` tags in config/Kconfig.*).
ROBOT_ONLY_DEFAULTS = ("use-robot", "rc-input", "geofence")


def test_profile_defconfigs_generic_robot_variants_robot() -> None:
    """Owner decision (wave 11): the profile defconfigs (edge, embedded,
    fleet) are Generic; each has a robot-<profile> twin that selects
    PRESET_ROBOT and differs from it in the preset line only. Every other
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
            if d.stem in OTHER_KERNEL_DEFCONFIGS:
                continue
            feats = _bridge_args(cfg)
            if d.stem in PROFILE_DEFCONFIGS or d.stem in GUEST_KERNEL_DEFCONFIGS:
                assert "use-robot" not in feats, f"{d.name}: {feats}"
            else:
                assert "use-robot" in feats, f"{d.name}: no use-robot in {feats}"
        # "Differs in the domain only" is a property of what each file SETS,
        # plus: the domain switch alone explains every expanded value. It is
        # not "no expanded value outside the Robot menu changes": a symbol may
        # take a per-domain default anywhere (FS_WRITEBACK_MAX_AGE_MS: 1 s in
        # the robot domain, 5 s elsewhere), as CONFIGURABILITY asks of every
        # symbol, and a list of Robot-menu name prefixes misses the menu's own
        # new symbols (MOTOR_COMMANDER_EXIT_STOP).
        settings = lambda ls: [l for l in ls if l.startswith("CONFIG_")
                               or re.fullmatch(r"# CONFIG_\w+ is not set", l)]
        for p in PROFILE_DEFCONFIGS:
            assert f"robot-{p}" in expanded, f"no robot-{p}.config"
            g = settings((DEFCONFIGS_DIR / f"{p}.config").read_text(encoding="utf-8").splitlines())
            r = settings((DEFCONFIGS_DIR / f"robot-{p}.config").read_text(encoding="utf-8").splitlines())
            diff = [l for l in r if l not in g] + [l for l in g if l not in r]
            assert sorted(diff) == ["CONFIG_PRESET_GENERIC=y", "CONFIG_PRESET_ROBOT=y"], \
                f"robot-{p} sets more than the preset beyond {p}: {diff}"
            switched = _expand([l for l in g if l != "CONFIG_PRESET_GENERIC=y"]
                               + ["CONFIG_PRESET_ROBOT=y"], t, f"switched-{p}.config")
            g2 = [l for l in switched if l.startswith("CONFIG_")]
            r2 = [l for l in expanded[f"robot-{p}"] if l.startswith("CONFIG_")]
            diff = [l for l in r2 if l not in g2] + [l for l in g2 if l not in r2]
            assert not diff, f"robot-{p} differs from {p} + PRESET_ROBOT: {diff}"


def test_generic_drops_only_the_domain_feature() -> None:
    """`make config` from scratch is Generic: the bridge emits the always-on
    base features and none of the robot ones."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        out = _expand([], t, "g.config")
        assert "CONFIG_USE_GENERIC=y" in out
        feats = _bridge_args(t / "g.config")
        for f in ROBOT_ONLY_DEFAULTS:
            assert f not in feats, f"Generic emitted the robot feature {f}: {feats}"
        for f in ALWAYS_BASE + FULL_PROFILE_BASE:
            assert f in feats, f"Generic lost the base feature {f}: {feats}"
        # The other non-robot domains build the same way.
        for dom in ("IOT_HMI", "GATEWAY", "INDUSTRIAL"):
            _expand([f"CONFIG_PRESET_{dom}=y"], t, f"{dom}.config")
            feats = _bridge_args(t / f"{dom}.config")
            assert "use-robot" not in feats, f"{dom}: {feats}"
        _expand(["CONFIG_PRESET_ROBOT=y"], t, "r.config")
        feats = _bridge_args(t / "r.config")
        assert all(f in feats for f in ROBOT_ONLY_DEFAULTS + ALWAYS_BASE), f"Robot: {feats}"


def test_scheduler_options_follow_their_symbols() -> None:
    """SCHED_O1_PLACEMENT / SCHED_TIMER_HEAP / SCHED_IPC_AFFINITY are y by
    default and each, set n, drops exactly its own feature."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for sym, feat in (("SCHED_O1_PLACEMENT", "sched-o1-placement"),
                          ("SCHED_TIMER_HEAP", "sched-timer-heap"),
                          ("SCHED_IPC_AFFINITY", "sched-ipc-affinity")):
            _expand([f"# CONFIG_{sym} is not set"], t, f"{sym}.config")
            feats = _bridge_args(t / f"{sym}.config")
            assert feat not in feats, f"{sym}=n kept {feat}: {feats}"
            assert [f for f in ALWAYS_BASE if f != feat and f not in feats] == [], feats


def test_refusal_receipts_follow_their_symbol() -> None:
    """DECISION_REFUSALS_DURABLE is y by default on every preset and builds
    `decisions-durable`; n drops it. The ring's symbol, DECISION_RECORDS_DEV,
    is the `decisions` feature and is separate: y by default on every preset
    but a small board (owner 2026-10-22, receipts on), a `base` tag, and n
    drops it alone.
    Canary: remove the `# cargo-feature:` tag (or its `base`) from a symbol ->
    the y case loses the feature."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for dom in ("ROBOT", "GENERIC"):
            _expand([f"CONFIG_PRESET_{dom}=y"], t, f"{dom}.config")
            feats = _bridge_args(t / f"{dom}.config")
            assert "decisions-durable" in feats and "decisions" in feats, f"{dom}: {feats}"
            base = subprocess.run([sys.executable, str(TOOLS_DIR / "kconfig_to_cargo.py"), "--base",
                                   str(t / f"{dom}.config")], capture_output=True, text=True).stdout
            assert "decisions," in base or base.rstrip().endswith("decisions"), f"{dom} --base: {base}"
        _expand(["CONFIG_PRESET_ROBOT=y", "CONFIG_DECISION_REFUSALS_DURABLE=n"], t, "off.config")
        feats = _bridge_args(t / "off.config")
        assert "decisions-durable" not in feats and "decisions" in feats, f"n kept or dropped: {feats}"
        _expand(["CONFIG_PRESET_ROBOT=y", "# CONFIG_DECISION_RECORDS_DEV is not set"], t, "dev.config")
        feats = _bridge_args(t / "dev.config")
        assert "decisions" not in feats and "decisions-durable" in feats, feats
        for small in (["CONFIG_PRESET_FIRMWARE=y"], ["CONFIG_PRESET_ROBOT=y", "CONFIG_HWCLASS_EMBEDDED=y"]):
            exp = _expand(small, t, "small.config")
            assert "# CONFIG_DECISION_RECORDS_DEV is not set" in exp, f"{small}: the ring is on a small board"


def test_virtio_input_follows_its_symbol() -> None:
    """DRV_VIRTIO_INPUT is y by default on every board and domain and builds
    `virtio-input` (a `base` tag); n drops it and nothing else.
    Canary: remove the tag from the symbol -> the y cases lose the feature."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for name, lines in (("robot", ["CONFIG_PRESET_ROBOT=y"]), ("generic", ["CONFIG_PRESET_GENERIC=y"]),
                            ("k1", ["CONFIG_BOARD_K1=y"]), ("a64", ["CONFIG_ARCH_AARCH64=y"]),
                            ("x86", ["CONFIG_ARCH_X86_64=y"])):
            exp = _expand(lines, t, f"{name}.config")
            assert "CONFIG_DRV_VIRTIO_INPUT=y" in exp, f"{name}: the symbol is not y by default"
            feats = _bridge_args(t / f"{name}.config")
            assert "virtio-input" in feats, f"{name}: {feats}"
        _expand(["CONFIG_PRESET_ROBOT=y", "# CONFIG_DRV_VIRTIO_INPUT is not set"], t, "off.config")
        feats = _bridge_args(t / "off.config")
        assert "virtio-input" not in feats, f"n kept the feature: {feats}"
        assert "use-robot" in feats and "rc-input" in feats, f"n dropped more than itself: {feats}"


def test_virtio_snd_follows_its_symbol() -> None:
    """DRV_VIRTIO_SND is y by default off the embedded profile and builds
    `virtio-snd` (a `base` tag); n drops it and nothing else, and the embedded
    profile (a small board with no virtual hardware) does not have it.
    Canary: remove the tag from the symbol -> the y cases lose the feature."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for name, lines in (("robot", ["CONFIG_PRESET_ROBOT=y"]), ("generic", ["CONFIG_PRESET_GENERIC=y"]),
                            ("a64", ["CONFIG_ARCH_AARCH64=y"]), ("x86", ["CONFIG_ARCH_X86_64=y"])):
            exp = _expand(lines, t, f"{name}.config")
            assert "CONFIG_DRV_VIRTIO_SND=y" in exp, f"{name}: the symbol is not y by default"
            feats = _bridge_args(t / f"{name}.config")
            assert "virtio-snd" in feats, f"{name}: {feats}"
        _expand(["CONFIG_PRESET_ROBOT=y", "# CONFIG_DRV_VIRTIO_SND is not set"], t, "off.config")
        feats = _bridge_args(t / "off.config")
        assert "virtio-snd" not in feats, f"n kept the feature: {feats}"
        assert "use-robot" in feats and "virtio-input" in feats, f"n dropped more than itself: {feats}"


def test_console_scrollback_follows_the_hardware_class() -> None:
    """FB_CONSOLE_SCROLLBACK is 200 lines on the desktop, server and sbc
    presets and 0 on HWCLASS_EMBEDDED (the firmware and wearable presets, and
    any preset forced onto a small board); a value set by hand wins inside the
    symbol's range 0..4096 and is refused outside it.
    Canary: drop the HWCLASS_EMBEDDED default -> the firmware row reads 200."""
    import tempfile

    def val(lines: list[str], t: Path, name: str) -> str:
        out = _expand(lines, t, name)
        got = [l for l in out if l.startswith("CONFIG_FB_CONSOLE_SCROLLBACK=")]
        assert len(got) == 1, f"{name}: {got}"
        return got[0].split("=", 1)[1]

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for preset, want in (("DESKTOP", "200"), ("SERVER", "200"), ("GENERIC", "200"), ("ROBOT", "200"),
                             ("IOT_HMI", "200"), ("FIRMWARE", "0"), ("WEARABLE", "0")):
            got = val([f"CONFIG_PRESET_{preset}=y"], t, f"{preset}.config")
            assert got == want, f"PRESET_{preset}: scrollback {got}, expected {want}"
        assert val(["CONFIG_PRESET_ROBOT=y", "CONFIG_HWCLASS_EMBEDDED=y"], t, "re.config") == "0", \
            "a robot preset forced onto a small board drops the scrollback ring"
        assert val(["CONFIG_PRESET_FIRMWARE=y", "CONFIG_FB_CONSOLE_SCROLLBACK=64"], t, "hand.config") == "64", \
            "a hand-set value lost to the preset"
        assert val(["CONFIG_PRESET_DESKTOP=y", "CONFIG_FB_CONSOLE_SCROLLBACK=4096"], t, "max.config") == "4096"
        assert val(["CONFIG_PRESET_DESKTOP=y", "CONFIG_FB_CONSOLE_SCROLLBACK=4097"], t, "hi.config") == "200", \
            "the symbol accepted a value above its range"


def test_ps2_is_x86_only_and_follows_the_domain() -> None:
    """DRV_PS2 (the i8042 keyboard and mouse) exists on x86_64 only, is y for
    the Generic and Desktop domains and n for Robot and Industrial, and builds
    `ps2` (a `base` tag) exactly when it is y.
    Canary: drop `depends on ARCH_X86_64` -> the riscv64/aarch64 cases get it."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for use, want in (("GENERIC", True), ("DESKTOP", True), ("ROBOT", False), ("INDUSTRIAL", False)):
            name = f"x86-{use}.config"
            exp = _expand(["CONFIG_ARCH_X86_64=y", f"CONFIG_PRESET_{use}=y"], t, name)
            assert ("CONFIG_DRV_PS2=y" in exp) == want, f"x86 {use}: DRV_PS2 default is not {want}"
            assert ("ps2" in _bridge_args(t / name)) == want, f"x86 {use}: feature `ps2` does not follow the symbol"
        for arch in ("RISCV64", "AARCH64"):
            name = f"{arch}.config"
            exp = _expand([f"CONFIG_ARCH_{arch}=y", "CONFIG_PRESET_DESKTOP=y"], t, name)
            assert "CONFIG_DRV_PS2=y" not in exp, f"{arch}: DRV_PS2 is y off x86_64"
            assert "ps2" not in _bridge_args(t / name), f"{arch}: the build got `ps2`"
        _expand(["CONFIG_ARCH_X86_64=y", "CONFIG_PRESET_DESKTOP=y", "# CONFIG_DRV_PS2 is not set"], t, "off.config")
        assert "ps2" not in _bridge_args(t / "off.config"), "n kept the feature"


def test_robot_subsystem_off_drops_its_feature() -> None:
    """Wave 15: RC_INPUT=n / GEOFENCE=n on a Robot .config builds without
    that one feature, keeping `use-robot` and
    the other subsystem: off compiles it out."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        for sym, feat, other in (("RC_INPUT", "rc-input", "geofence"),
                                 ("GEOFENCE", "geofence", "rc-input")):
            _expand(["CONFIG_PRESET_ROBOT=y", f"# CONFIG_{sym} is not set"], t, f"{sym}.config")
            feats = _bridge_args(t / f"{sym}.config")
            assert feat not in feats, f"{sym}=n still emitted {feat}: {feats}"
            assert "use-robot" in feats and other in feats, f"{sym}=n: {feats}"


def test_iot_hmi_implies_display() -> None:
    """IoT-HMI turns on the board's display by default; it can still be turned
    off, and another domain does not turn it on."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        q = _expand(["CONFIG_PRESET_IOT_HMI=y"], t, "q.config")
        assert "CONFIG_DRV_DISPLAY_RAMFB=y" in q, "QEMU riscv64"
        feats = _bridge_args(t / "q.config")
        assert "ramfb" in feats, f"QEMU riscv64: {feats}"
        v = _expand(["CONFIG_PRESET_IOT_HMI=y", "CONFIG_BOARD_VF2=y"], t, "v.config")
        assert "CONFIG_DRV_DISPLAY_HDMI=y" in v, "VF2"
        a = _expand(["CONFIG_PRESET_IOT_HMI=y", "CONFIG_ARCH_AARCH64=y"], t, "a.config")
        assert not any(l.startswith("CONFIG_DRV_DISPLAY_RAMFB=y") for l in a), (
            "ramfb implied on aarch64, where it does not build")
        off = _expand(["CONFIG_PRESET_IOT_HMI=y", "# CONFIG_DRV_DISPLAY_RAMFB is not set"], t, "o.config")
        assert "# CONFIG_DRV_DISPLAY_RAMFB is not set" in off, "imply forced the display on"
        g = _expand([], t, "g.config")
        assert "# CONFIG_DRV_DISPLAY_RAMFB is not set" in g


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
        g = _expand(["CONFIG_PRESET_GATEWAY=y"], t, "g.config")
        for sym, val in GATEWAY_EDGE.items():
            assert _value(g, sym) == val, f"Gateway/Edge {sym}={_value(g, sym)}, want {val}"
        e = _expand([], t, "e.config")
        for sym, val in EDGE.items():
            assert _value(e, sym) == val, f"Generic/Edge {sym}={_value(e, sym)}, want {val}"
        h = _expand(["CONFIG_PRESET_GATEWAY=y", "CONFIG_TCP_MAX_CONNS=12"], t, "h.config")
        assert _value(h, "TCP_MAX_CONNS") == "12", "a hand-set TCP_MAX_CONNS lost to the domain"
        f = _expand(["CONFIG_PRESET_GATEWAY=y", "CONFIG_HWCLASS_SERVER=y"], t, "f.config")
        assert _value(f, "TCP_MAX_CONNS") == "1024", "Gateway overrode the Fleet profile"
        # The limits crate's own checks accept the Gateway values.
        assert int(GATEWAY_EDGE["MAX_SOCKETS"]) >= int(GATEWAY_EDGE["TCP_MAX_CONNS"]) + 4
        n = int(GATEWAY_EDGE["UDP_RX_SLOTS"])
        assert n & (n - 1) == 0


def test_industrial_preset_starts_with_the_physical_access_threat_model() -> None:
    """The industrial preset sets SECURITY separation-static, the physical-access
    threat model (and so its implied mitigations); the user can still pick
    another posture."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        i = _expand(["CONFIG_PRESET_INDUSTRIAL=y"], t, "i.config")
        assert "CONFIG_USE_INDUSTRIAL=y" in i and "CONFIG_SECURITY_SEPARATION_STATIC=y" in i
        for sym in ("CONSOLE_LOCKDOWN", "SECURE_BOOT_ENFORCED", "OTA_SIG_MANDATORY"):
            assert f"CONFIG_{sym}=y" in i, f"Industrial did not get {sym}"
        feats = _bridge_args(t / "i.config")
        assert "secure-boot-enforced" in feats, f"Industrial: {feats}"
        back = _expand(["CONFIG_PRESET_INDUSTRIAL=y", "CONFIG_SECURITY_GENERAL=y"], t, "b.config")
        assert "CONFIG_SECURITY_GENERAL=y" in back, "the domain forced the security posture"
        assert "# CONFIG_CONSOLE_LOCKDOWN is not set" in back, "the general posture kept the lockdown"
        g = _expand([], t, "g.config")
        assert "CONFIG_SECURITY_GENERAL=y" in g


def test_microkernel_implies_ring3_placement() -> None:
    """Wave 11 (DRVPLACE): STRUCTURE ring3-drivers implies DRV_RING3_DEFAULT, which every
    driver placement choice follows, and changes nothing else; the imply can
    be turned off and each placement set by hand."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        strip = lambda ls: [l for l in ls if "STRUCTURE_" not in l]
        g = strip(_expand([], t, "g.config"))
        m = strip(_expand(["CONFIG_STRUCTURE_RING3_DRIVERS=y"], t, "m.config"))
        assert "CONFIG_DRV_RING3_DEFAULT=y" in m and "CONFIG_DRV_INA219_PLACEMENT_RING3=y" in m, m
        assert "# CONFIG_DRV_RING3_DEFAULT is not set" in g, "Generic must not start in ring 3"
        diff = [l for l in m if l not in g] + [l for l in g if l not in m]
        assert sorted(diff) == sorted(["CONFIG_DRV_RING3_DEFAULT=y",
                                       "# CONFIG_DRV_RING3_DEFAULT is not set"]), diff
        off = _expand(["CONFIG_STRUCTURE_RING3_DRIVERS=y", "# CONFIG_DRV_RING3_DEFAULT is not set"],
                      t, "o.config")
        assert "# CONFIG_DRV_RING3_DEFAULT is not set" in off, "the imply forced DRV_RING3_DEFAULT"
        k = _expand(["CONFIG_STRUCTURE_RING3_DRIVERS=y", "CONFIG_DRV_INA219_PLACEMENT_KERNEL=y"],
                    t, "k.config")
        assert "CONFIG_DRV_INA219_PLACEMENT_KERNEL=y" in k, "a hand-set placement lost to the domain"
        assert "CONFIG_DRV_BUZZER_PLACEMENT_RING3=y" in m, "the buzzer did not follow DRV_RING3_DEFAULT"


def test_presets_set_the_axes_and_certifiable_forces_signing() -> None:
    """D1: a preset sets the axes through defaults only (a hand-set axis wins);
    CERTIFIABLE forces secure boot and signed OTA on, cannot be had on QEMU,
    and RT hard refuses demand paging without the RT pre-commit."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        r = _expand(["CONFIG_PRESET_ROBOT=y"], t, "r.config")
        for want in ("CONFIG_USE_ROBOT=y", "CONFIG_RT_HARD=y", "CONFIG_HWCLASS_SBC=y",
                     "CONFIG_SECURITY_GENERAL=y", "CONFIG_VIRT_NONE=y",
                     "CONFIG_DECISION_REFUSALS_DURABLE=y"):
            assert want in r, f"PRESET_ROBOT: {want} missing"
        s = _expand(["CONFIG_PRESET_SERVER=y", "CONFIG_ARCH_X86_64=y"], t, "s.config")
        for want in ("CONFIG_USE_SERVER=y", "CONFIG_HWCLASS_SERVER=y",
                     "CONFIG_SECURITY_HARDENED=y", "CONFIG_VIRT_HOSTED=y",
                     "CONFIG_OTA_SIG_MANDATORY=y"):
            assert want in s, f"PRESET_SERVER: {want} missing"
        i = _expand(["CONFIG_PRESET_INDUSTRIAL=y"], t, "i.config")
        assert "CONFIG_VIRT_STATIC=y" in i and "# CONFIG_MM_DEMAND_PAGING is not set" in i, i
        hand = _expand(["CONFIG_PRESET_ROBOT=y", "CONFIG_RT_SOFT=y"], t, "h.config")
        assert "CONFIG_RT_SOFT=y" in hand, "a hand-set RT lost to the preset"
        c = _expand(["CONFIG_BOARD_VF2=y", "CONFIG_BUILD_TYPE_CERTIFIABLE=y",
                     "# CONFIG_SECURE_BOOT_ENFORCED is not set",
                     "# CONFIG_OTA_SIG_MANDATORY is not set"], t, "c.config")
        assert "CONFIG_BUILD_TYPE_CERTIFIABLE=y" in c
        assert "CONFIG_SECURE_BOOT_ENFORCED=y" in c and "CONFIG_OTA_SIG_MANDATORY=y" in c, \
            "CERTIFIABLE did not force secure boot and signed OTA"
        assert "secure-boot-enforced" in _bridge_args(t / "c.config")
        q = _expand(["CONFIG_BUILD_TYPE_CERTIFIABLE=y"], t, "q.config")
        assert "CONFIG_BUILD_TYPE_CERTIFIABLE=y" not in q, "CERTIFIABLE on the QEMU board"
        n = _expand(["CONFIG_PRESET_ROBOT=y", "# CONFIG_MM_PRECOMMIT_RT is not set"], t, "n.config")
        assert "CONFIG_RT_HARD=y" not in n, "RT hard with demand paging and no RT pre-commit"


def test_driver_placement_reaches_the_build() -> None:
    """DRV_INA219_PLACEMENT: `kernel` is the kernel feature `ina219-kernel`,
    from the full bridge and from `--base` (`make build`); `ring3`
    (the default) is no feature, as a build naming its features by hand."""
    import tempfile

    script = TOOLS_DIR / "kconfig_to_cargo.py"
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        d = _expand([], t, "d.config")
        assert "CONFIG_DRV_INA219_PLACEMENT_RING3=y" in d, "the default placement is not ring3"
        feats = _bridge_args(t / "d.config")
        assert "ina219-kernel" not in feats, feats
        for dom in ([], ["CONFIG_PRESET_ROBOT=y"]):
            _expand(dom + ["CONFIG_DRV_INA219_PLACEMENT_KERNEL=y"], t, "k.config")
            feats = _bridge_args(t / "k.config")
            assert "ina219-kernel" in feats, (dom, feats)
            out = subprocess.run([sys.executable, str(script), "--base", str(t / "k.config")],
                                 capture_output=True, text=True, check=True).stdout
            assert "ina219-kernel" in out, (dom, out)
        # Wave 12: the buzzer's choice, the same way.
        assert "CONFIG_DRV_BUZZER_PLACEMENT_RING3=y" in d, "the buzzer's default is not ring3"
        assert "buzzer-kernel" not in feats or "CONFIG_DRV_BUZZER_PLACEMENT_KERNEL=y" in d, feats
        _expand(["CONFIG_DRV_BUZZER_PLACEMENT_KERNEL=y"], t, "b.config")
        feats = _bridge_args(t / "b.config")
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


def test_base_for_hand_written_targets() -> None:
    """`--base` (used by `make build`, which names `--features qemu` itself)
    prints only the base features, never the board or the target."""
    import tempfile

    script = TOOLS_DIR / "kconfig_to_cargo.py"
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _expand([], t, "g.config")
        _expand(["CONFIG_PRESET_ROBOT=y"], t, "r.config")
        run = lambda c: subprocess.run([sys.executable, str(script), "--base", str(c)],
                                       capture_output=True, text=True, check=True).stdout.split()
        g = run(t / "g.config")
        assert g[0] == "--features" and "--target" not in g, g
        assert "qemu" not in g[1].split(","), g
        assert sorted(g[1].split(",")) == sorted(ALWAYS_BASE + FULL_PROFILE_BASE), g
        r = run(t / "r.config")
        assert "use-robot" in r[1].split(",") and "qemu" not in r[1].split(","), r


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
        test_x86_64_level_and_require_reach_the_codegen,
        test_lx_server_skeleton_reaches_the_build,
        test_profile_defconfigs_generic_robot_variants_robot,
        test_generic_drops_only_the_domain_feature,
        test_refusal_receipts_follow_their_symbol,
        test_virtio_input_follows_its_symbol,
        test_virtio_snd_follows_its_symbol,
        test_ps2_is_x86_only_and_follows_the_domain,
        test_iot_hmi_implies_display,
        test_gateway_raises_network_defaults_on_edge,
        test_industrial_preset_starts_with_the_physical_access_threat_model,
        test_microkernel_implies_ring3_placement,
        test_presets_set_the_axes_and_certifiable_forces_signing,
        test_driver_placement_reaches_the_build,
        test_a_safety_read_driver_is_never_placed_in_ring3,
        test_base_for_hand_written_targets,
        test_scheduler_options_follow_their_symbols,
        test_kaslr_links_position_independent,
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
