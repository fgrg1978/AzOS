#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_board_manifest.py — host unit tests for the board-image ELF derivation.

Covers `tools/gen_board_manifest.py` (pre-build: topology declares a service
nothing builds) and `tools/check_board_disk.py` (post-build: the built disk
image and the topology-declared manifest disagree). Both failure modes the
owner asked for — orphan ELF, orphan service — are exercised here against
the pure functions directly, so they run without cargo, mtools or QEMU.

Run with:
    python3 tools/test_board_manifest.py
"""

import importlib.util
import sys
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).parent.resolve()


def _load(module_name, file_name):
    spec = importlib.util.spec_from_file_location(module_name, TOOLS_DIR / file_name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen_board_manifest = _load("gen_board_manifest", "gen_board_manifest.py")
check_board_disk = _load("check_board_disk", "check_board_disk.py")
check_board_keys = _load("check_board_keys", "check_board_keys.py")


class ComputeManifestTests(unittest.TestCase):
    """tools/gen_board_manifest.py::compute_manifest — the pre-build check."""

    def test_every_declared_service_has_a_build_path(self):
        declared = ["GPIODRV.ELF", "REFLEX.ELF", "BRAINCLI.ELF"]
        available = {
            "GPIODRV.ELF": "elfs/gpio_drv.elf",
            "REFLEX.ELF": "elfs/reflex.elf",
            "BRAINCLI.ELF": "elfs/brain_client.elf",
            # Extra buildable ELFs that are NOT declared (test images) must
            # not leak onto the board manifest just because they exist.
            "ABITEST.ELF": "elfs/abitest.elf",
        }
        manifest, orphans = gen_board_manifest.compute_manifest(declared, available)
        self.assertEqual(orphans, [])
        self.assertEqual(
            manifest,
            [
                ("GPIODRV.ELF", "elfs/gpio_drv.elf"),
                ("REFLEX.ELF", "elfs/reflex.elf"),
                ("BRAINCLI.ELF", "elfs/brain_client.elf"),
            ],
        )

    def test_orphan_service_topology_declares_an_unbuilt_elf(self):
        """RED CASE 1: the topology names an ELF nothing in the tree builds."""
        declared = ["GPIODRV.ELF", "GHOSTDRV.ELF"]
        available = {"GPIODRV.ELF": "elfs/gpio_drv.elf"}
        manifest, orphans = gen_board_manifest.compute_manifest(declared, available)
        self.assertEqual(orphans, ["GHOSTDRV.ELF"])
        self.assertEqual(manifest, [("GPIODRV.ELF", "elfs/gpio_drv.elf")])

    def test_duplicate_declared_names_do_not_duplicate_the_manifest(self):
        declared = ["GPIODRV.ELF", "GPIODRV.ELF"]
        available = {"GPIODRV.ELF": "elfs/gpio_drv.elf"}
        manifest, orphans = gen_board_manifest.compute_manifest(declared, available)
        self.assertEqual(orphans, [])
        self.assertEqual(manifest, [("GPIODRV.ELF", "elfs/gpio_drv.elf")])


class SelectedImagesTests(unittest.TestCase):
    """tools/gen_board_manifest.py::selected_images — `make config`'s
    "Userspace programs" choices on top of the topology's images."""

    AVAILABLE = {"SH.ELF": "elfs/sh.elf", "HELLO.ELF": "elfs/hello.elf", "UHELLO.ELF": "elfs/uhello.elf"}

    def test_a_selected_image_ships_beside_the_declared_ones(self):
        cfg = "CONFIG_USERSPACE_SH=y\nCONFIG_USERSPACE_HELLO=y\n# CONFIG_USERSPACE_UHELLO is not set\n"
        extras, unselected, dropped = gen_board_manifest.selected_images(cfg, ["SH.ELF"], self.AVAILABLE)
        self.assertEqual(extras, ["HELLO.ELF"])
        self.assertEqual(unselected, [])
        self.assertEqual(dropped, [])

    def test_a_declared_image_left_out_is_reported(self):
        cfg = "# CONFIG_USERSPACE_SH is not set\n"
        _, unselected, dropped = gen_board_manifest.selected_images(cfg, ["SH.ELF"], self.AVAILABLE)
        self.assertEqual(unselected, ["SH.ELF"])
        self.assertEqual(dropped, [])

    def test_a_small_board_leaves_the_declared_images_it_does_not_build_out(self):
        cfg = ("CONFIG_HWCLASS_EMBEDDED=y\nCONFIG_USERSPACE_SH=y\n# CONFIG_USERSPACE_POWER is not set\n"
               "CONFIG_USERSPACE_HELLO=y\n")
        available = dict(self.AVAILABLE, **{"POWER.ELF": "elfs/power.elf"})
        extras, unselected, dropped = gen_board_manifest.selected_images(cfg, ["SH.ELF", "POWER.ELF"], available)
        self.assertEqual(unselected, [])
        self.assertEqual(dropped, ["POWER.ELF"])
        self.assertEqual(extras, ["HELLO.ELF"])


class CheckBoardDiskTests(unittest.TestCase):
    """tools/check_board_disk.py::diff — the post-build anti-drift check."""

    def test_disk_matches_declared_manifest(self):
        disk_names = {"GPIODRV.ELF", "REFLEX.ELF", "BRAINCLI.ELF"}
        declared_names = {"GPIODRV.ELF", "REFLEX.ELF", "BRAINCLI.ELF"}
        orphan_elfs, orphan_services = check_board_disk.diff(disk_names, declared_names)
        self.assertEqual(orphan_elfs, [])
        self.assertEqual(orphan_services, [])

    def test_orphan_elf_on_disk_with_no_providing_topology_entry(self):
        """RED CASE 2: an ELF is on the image that no topology row declares —
        e.g. a hand-added `mcopy` line the generator did not produce."""
        disk_names = {"GPIODRV.ELF", "REFLEX.ELF", "BRAINCLI.ELF", "CAPTEST.ELF"}
        declared_names = {"GPIODRV.ELF", "REFLEX.ELF", "BRAINCLI.ELF"}
        orphan_elfs, orphan_services = check_board_disk.diff(disk_names, declared_names)
        self.assertEqual(orphan_elfs, ["CAPTEST.ELF"])
        self.assertEqual(orphan_services, [])

    def test_orphan_service_declared_but_never_shipped(self):
        """A name the topology declares that somehow never made it onto the
        built image — the manifest and the actual disk disagree the other
        way."""
        disk_names = {"GPIODRV.ELF", "REFLEX.ELF"}
        declared_names = {"GPIODRV.ELF", "REFLEX.ELF", "BRAINCLI.ELF"}
        orphan_elfs, orphan_services = check_board_disk.diff(disk_names, declared_names)
        self.assertEqual(orphan_elfs, [])
        self.assertEqual(orphan_services, ["BRAINCLI.ELF"])

    def test_mdir_output_parses_only_dot_elf_tokens(self):
        # Real `mdir -i disk.img ::` output (verified against a scratch FAT32
        # image built with `mkfs.fat`+`mcopy`): each row repeats the name in
        # 8.3-split form ("GPIODRV  ELF") AND as a trailing long name
        # ("GPIODRV.ELF"). Only the trailing token carries the dot, so it is
        # the only one `endswith(".ELF")` matches — the split "ELF" token
        # does not.
        sample = (
            " Volume in drive : is TEST       __\n"
            " Volume Serial Number is F714-19F0\n"
            "Directory for ::/\n"
            "\n"
            "GPIODRV  ELF         6 2026-09-24  16:10  GPIODRV.ELF\n"
            "CONFIG   INI         3 2026-09-24  16:10  CONFIG.INI\n"
            "        2 files                   9 bytes\n"
            "                          4 111 872 bytes free\n"
        )
        names = check_board_disk.parse_mdir_elf_names(sample)
        self.assertEqual(names, {"GPIODRV.ELF"})


class CheckBoardKeysTests(unittest.TestCase):
    """tools/check_board_keys.py — a board image never carries the test key."""

    TEST = bytes(range(32))
    NAMED = bytes(range(100, 132))

    def test_named_key_is_accepted(self):
        self.assertIsNone(check_board_keys.check_key(self.NAMED, self.TEST))

    def test_test_key_is_refused(self):
        self.assertIn("TEST key", check_board_keys.check_key(self.TEST, self.TEST))

    def test_wrong_length_key_is_refused(self):
        self.assertIn("bytes", check_board_keys.check_key(b"short", self.TEST))

    def test_missing_test_key_file_skips_only_the_comparison(self):
        self.assertIsNone(check_board_keys.check_key(self.NAMED, None))

    def test_board_elf_with_named_key_passes(self):
        elf = b"\x7fELF" + b"\0" * 40 + self.NAMED + b"\0" * 40
        self.assertIsNone(check_board_keys.check_elf(elf, self.NAMED, self.TEST))

    def test_elf_with_test_key_fails_even_when_it_also_has_the_named_one(self):
        elf = b"\x7fELF" + self.NAMED + b"\0" * 8 + self.TEST
        self.assertIn("TEST key", check_board_keys.check_elf(elf, self.NAMED, self.TEST))

    def test_elf_without_the_named_key_fails(self):
        self.assertIn("does not embed",
                      check_board_keys.check_elf(b"\x7fELF" + b"\0" * 64, self.NAMED, self.TEST))

    def _table(self, digest):
        rows = ", ".join("0x%02x" % b for b in digest)
        return 'pub const IMAGE_SHA256: &[(&str, [u8; 32])] = &[\n("MLSRV.ELF", [%s]),\n];\n' % rows

    def test_disk_mlsrv_matching_the_board_table_passes(self):
        import hashlib
        board = b"board" + self.NAMED
        qemu = b"qemu" + self.TEST
        table = self._table(hashlib.sha256(board).digest())
        self.assertIsNone(check_board_keys.check_disk(board, table, qemu, self.TEST))

    def test_disk_mlsrv_that_is_the_qemu_build_fails(self):
        import hashlib
        qemu = b"qemu" + self.TEST
        table = self._table(hashlib.sha256(qemu).digest())
        self.assertIsNotNone(check_board_keys.check_disk(qemu, table, qemu, self.TEST))

    def test_disk_mlsrv_not_in_the_table_fails(self):
        import hashlib
        table = self._table(hashlib.sha256(b"other").digest())
        self.assertIn("lists", check_board_keys.check_disk(b"board", table, None, None))

    def test_pair_matching_named_key_is_accepted(self):
        seed = bytes(range(50, 82))
        pub = check_board_keys.derive_public(seed)
        self.assertIsNone(check_board_keys.check_pair(seed, pub, self.TEST, self.TEST))

    def test_pair_with_a_mismatched_public_half_is_refused(self):
        seed = bytes(range(50, 82))
        other = check_board_keys.derive_public(bytes(range(60, 92)))
        self.assertIn("not the private half", check_board_keys.check_pair(seed, other, None, None))

    def test_pair_signing_with_the_test_private_key_is_refused(self):
        pub = check_board_keys.derive_public(self.TEST)
        self.assertIn("TEST key", check_board_keys.check_pair(self.TEST, pub, self.TEST, None))

    def test_pair_whose_public_half_is_the_test_public_key_is_refused(self):
        seed = bytes(range(50, 82))
        pub = check_board_keys.derive_public(seed)
        self.assertIn("TEST key", check_board_keys.check_pair(seed, pub, None, pub))


class AllowTestFlagTests(unittest.TestCase):
    """`check_board_keys.py --allow-test`: the vf2 development image (BUILD_TYPE=DEV)."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        seed = bytes(range(50, 82))
        self.test_priv = self._write("test_priv.bin", seed)
        self.test_pub = self._write("test_pub.bin", check_board_keys.derive_public(seed))
        other = bytes(range(60, 92))
        self.fleet_priv = self._write("fleet_priv.bin", other)
        self.fleet_pub = self._write("fleet_pub.bin", check_board_keys.derive_public(other))

    def _write(self, name, data):
        path = str(Path(self.dir.name) / name)
        Path(path).write_bytes(data)
        return path

    def _run(self, *args):
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = check_board_keys.main(["check_board_keys.py", *args])
        return rc, err.getvalue()

    def test_release_refuses_the_test_key(self):
        rc, err = self._run("key", self.test_pub, self.test_pub)
        self.assertEqual(rc, 1)
        self.assertIn("TEST key", err)

    def test_dev_accepts_the_test_key(self):
        self.assertEqual(self._run("--allow-test", "key", self.test_pub, self.test_pub)[0], 0)

    def test_dev_still_refuses_a_key_of_the_wrong_length(self):
        short = self._write("short.bin", b"short")
        rc, err = self._run("--allow-test", "key", short, self.test_pub)
        self.assertEqual(rc, 1)
        self.assertIn("bytes", err)

    def test_release_refuses_the_test_pair(self):
        rc, err = self._run("pair", self.test_priv, self.test_pub, self.test_priv, self.test_pub)
        self.assertEqual(rc, 1)
        self.assertIn("TEST key", err)

    def test_dev_accepts_the_test_pair(self):
        self.assertEqual(self._run("--allow-test", "pair", self.test_priv, self.test_pub,
                                   self.test_priv, self.test_pub)[0], 0)

    def test_dev_still_refuses_a_private_key_of_another_public_key(self):
        rc, err = self._run("--allow-test", "pair", self.fleet_priv, self.test_pub,
                            self.test_priv, self.test_pub)
        self.assertEqual(rc, 1)
        self.assertIn("not the private half", err)

    def test_dev_accepts_an_elf_that_embeds_the_test_key(self):
        elf = self._write("mlsrv.elf", b"\x7fELF" + b"\0" * 16 + Path(self.test_pub).read_bytes())
        self.assertEqual(self._run("--allow-test", "elf", self.test_pub, self.test_pub, elf)[0], 0)
        self.assertEqual(self._run("elf", self.test_pub, self.test_pub, elf)[0], 1)

    def test_dev_still_needs_the_named_key_in_the_elf(self):
        elf = self._write("mlsrv.elf", b"\x7fELF" + b"\0" * 64)
        rc, err = self._run("--allow-test", "elf", self.test_pub, self.test_pub, elf)
        self.assertEqual(rc, 1)
        self.assertIn("does not embed", err)


if __name__ == "__main__":
    unittest.main()
