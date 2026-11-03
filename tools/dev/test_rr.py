#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_rr.py — host tests of tools/dev/rr_qemu.py, rr_row.sh and rr_replay.sh.

The refusals (what QEMU record/replay cannot reproduce), the record and replay
command lines, the failure marker and the console comparison, the record wrapper
end to end against a stand-in QEMU that prints its arguments, and the scripts'
argument checks. No QEMU runs: the three ISAs' recordings are made by hand (see
the tools/dev README section "Record and replay a gate row").

Run with:
    python3 tools/dev/test_rr.py
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../lib"))
import azos_tools  # noqa: E402,F401

import rr_qemu  # noqa: E402

KTEST_RV = ["-machine", "virt", "-nographic", "-bios", "default", "-kernel", "K", "-smp", "4"]
KTEST_ARM = ["-M", "virt,gic-version=3", "-cpu", "max,pauth=on", "-smp", "4", "-nographic",
             "-semihosting-config", "enable=on,target=native", "-kernel", "K"]
KTEST_X86 = ["-M", "microvm", "-cpu", "max", "-m", "256M", "-nographic", "-no-reboot",
             "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-smp", "4", "-kernel", "K"]
DISK = ["-drive", "file=D,if=none,format=raw,id=hd0", "-device", "virtio-blk-device,drive=hd0"]


class Refusals(unittest.TestCase):
    def test_gate_ktest_command_lines_are_taken(self):
        for argv in (KTEST_RV, KTEST_ARM, KTEST_X86, KTEST_RV + DISK, KTEST_RV + ["-append", "canary=x"]):
            self.assertEqual(rr_qemu.refusals(argv), [], argv)

    def test_hvf_and_kvm_are_refused_tcg_is_not(self):
        for a in (["-accel", "hvf"], ["-accel", "kvm"], ["-enable-kvm"], ["-machine", "virt,accel=hvf"], ["-cpu", "host"]):
            self.assertTrue(rr_qemu.refusals(KTEST_ARM + a), a)
        self.assertEqual(rr_qemu.refusals(KTEST_ARM + ["-accel", "tcg"]), [])
        self.assertEqual(rr_qemu.refusals(KTEST_ARM + ["-machine", "virt,accel=tcg"]), [])
        self.assertTrue(rr_qemu.refusals(KTEST_ARM + ["-accel", "tcg,thread=multi"]))

    def test_host_network_backends_are_refused_none_is_not(self):
        net = ["-netdev", "user,id=n0", "-device", "virtio-net-device,netdev=n0"]
        why = rr_qemu.refusals(KTEST_RV + net)
        self.assertTrue(any("network" in w for w in why), why)
        self.assertTrue(rr_qemu.refusals(KTEST_RV + ["-nic", "user"]))
        self.assertTrue(rr_qemu.refusals(KTEST_RV + ["-net", "tap"]))
        self.assertEqual(rr_qemu.refusals(KTEST_RV + ["-nic", "none"]), [])

    def test_outside_input_is_refused(self):
        for extra in (["-chardev", "socket,id=c,path=/x,server=on"], ["-serial", "tcp::4444,server=on"],
                      ["-gdb", "unix:/x/g,server=on,wait=off"], ["-monitor", "unix:/x/m,server=on,wait=off"],
                      ["-qmp", "unix:/x/q"], ["-s"], ["-S"], ["-display", "cocoa"], ["-vnc", ":0"],
                      ["-device", "usb-host,vendorid=1"], ["-virtfs", "local,path=/x"],
                      ["-object", "rng-random,id=r,filename=/dev/urandom"]):
            self.assertTrue(rr_qemu.refusals(KTEST_RV + extra), extra)
        self.assertEqual(rr_qemu.refusals(KTEST_RV + ["-display", "none"]), [])

    def test_disks_other_than_if_none_are_refused(self):
        for extra in (["-hda", "x.img"], ["-drive", "file=x,if=virtio"], ["-blockdev", "driver=file,node-name=a,filename=x"],
                      ["-drive", "file=x,if=pflash"], ["-drive", "if=none,id=a"]):
            self.assertTrue(rr_qemu.refusals(KTEST_RV + extra), extra)
        self.assertEqual(rr_qemu.refusals(KTEST_RV + ["-drive", "file=f,if=pflash,readonly=on"]), [])

    def test_a_command_that_already_records_is_refused(self):
        self.assertTrue(rr_qemu.refusals(KTEST_RV + ["-icount", "shift=0,rr=record,rrfile=x"]))
        self.assertEqual(rr_qemu.refusals(KTEST_RV + ["-icount", "shift=0,sleep=off"]), [])


class Commands(unittest.TestCase):
    def spec(self, argv, files):
        return {"argv": argv, "files": files, "rr": "rr.bin"}

    def test_record_adds_icount_and_the_rr_file(self):
        out = rr_qemu.final_args(self.spec(KTEST_RV, {"6": "kernel"}), "/d", "record")
        self.assertIn("/d/kernel", out)
        self.assertEqual(out[out.index("-icount") + 1], "shift=0,sleep=off,rr=record,rrfile=/d/rr.bin")
        self.assertEqual(out.count("-icount"), 1)
        self.assertNotIn("K", out)

    def test_an_existing_icount_is_merged_not_doubled(self):
        out = rr_qemu.final_args(self.spec(KTEST_RV + ["-icount", "shift=3,sleep=on"], {"6": "kernel"}), "/d", "record")
        self.assertEqual(out.count("-icount"), 1)
        self.assertEqual(out[out.index("-icount") + 1], "shift=3,sleep=on,rr=record,rrfile=/d/rr.bin")

    def test_disks_become_snapshot_plus_blkreplay_under_the_same_id(self):
        argv = KTEST_RV + DISK
        out = rr_qemu.final_args(self.spec(argv, {"6": "kernel", str(len(KTEST_RV) + 1): "disk-0.img"}), "/d", "record")
        drives = [out[i + 1] for i, a in enumerate(out) if a == "-drive"]
        self.assertEqual(drives[0], "file=/d/disk-0.img,if=none,format=raw,id=hd0-direct,snapshot=on")
        self.assertEqual(drives[1], "driver=blkreplay,if=none,image=hd0-direct,id=hd0")
        self.assertIn("virtio-blk-device,drive=hd0", out)

    def test_replay_differs_from_record_only_in_mode_and_the_stub(self):
        spec = self.spec(KTEST_RV, {"6": "kernel"})
        rec = rr_qemu.final_args(spec, "/d", "record")
        rep = rr_qemu.final_args(spec, "/d", "replay")
        self.assertEqual([a.replace("rr=record", "rr=replay") for a in rec], rep)
        dbg = rr_qemu.final_args(spec, "/d", "replay", 1234)
        self.assertEqual(dbg[-3:], ["-gdb", "tcp::1234", "-S"])

    def test_global_snapshot_is_dropped(self):
        out = rr_qemu.final_args(self.spec(KTEST_RV + ["-snapshot"], {"6": "kernel"}), "/d", "record")
        self.assertNotIn("-snapshot", out)


class Marker(unittest.TestCase):
    TAP = "1..3\nok 1 - a\nnot ok 2 - boom\nok 3 - c\n"

    def test_first_failure_line(self):
        self.assertEqual(rr_qemu.find_marker(self.TAP), "not ok 2 - boom")
        self.assertIsNone(rr_qemu.find_marker("1..1\nok 1 - a\n"))
        self.assertEqual(rr_qemu.find_marker("x\nKERNEL PANIC at y\n"), "KERNEL PANIC at y")

    def test_until_overrides_the_failure_pattern(self):
        self.assertEqual(rr_qemu.find_marker(self.TAP, r"^ok 3"), "ok 3 - c")

    def test_compare_identical_diverging_and_marker_missing(self):
        ok, msg = rr_qemu.compare(self.TAP, self.TAP.replace("\n", "\r\n"), "not ok 2 - boom")
        self.assertTrue(ok, msg)
        ok, msg = rr_qemu.compare(self.TAP, self.TAP.replace("boom", "bang"), "not ok 2 - boom")
        self.assertFalse(ok)
        self.assertIn("line 3", msg)
        ok, msg = rr_qemu.compare(self.TAP, self.TAP + "extra\n", None)
        self.assertFalse(ok)
        ok, msg = rr_qemu.compare("ok 1 - a\n", "ok 1 - a\n", "not ok 2 - boom")
        self.assertFalse(ok)


def slurp(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


FAKE_QEMU = """#!/bin/sh
printf '%s\\n' "$@" >"$FAKE_OUT"
echo 'ok 1 - fake'
"""


class Wrapper(unittest.TestCase):
    """The record wrapper, as qemu-system-riscv64 on PATH, in front of a QEMU that prints its arguments."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rrtest")
        self.real = os.path.join(self.tmp, "real")
        self.wrap = os.path.join(self.tmp, "wrap")
        self.rr = os.path.join(self.tmp, "rr")
        for d in (self.real, self.wrap, self.rr):
            os.mkdir(d)
        fake = os.path.join(self.real, "qemu-system-riscv64")
        with open(fake, "w") as f:
            f.write(FAKE_QEMU)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        os.symlink(os.path.join(HERE, "rr_qemu.py"), os.path.join(self.wrap, "qemu-system-riscv64"))
        self.kernel = os.path.join(self.tmp, "k.elf")
        self.disk = os.path.join(self.tmp, "d.img")
        with open(self.kernel, "wb") as f:
            f.write(b"ELF")
        with open(self.disk, "wb") as f:
            f.write(b"DISK")
        self.out = os.path.join(self.tmp, "args.txt")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_wrapper(self, args, rr=True):
        env = dict(os.environ, PATH=self.wrap + os.pathsep + self.real + os.pathsep + os.environ["PATH"], FAKE_OUT=self.out)
        env.pop("RR_DIR", None)
        if rr:
            env["RR_DIR"] = self.rr
        log = os.path.join(self.tmp, "console.txt")
        with open(log, "w") as f:
            p = subprocess.run(["qemu-system-riscv64"] + args, env=env, stdout=f, stderr=subprocess.PIPE, text=True)
        return p, log

    def test_record_keeps_the_kernel_and_disk_and_records(self):
        argv = ["-machine", "virt", "-nographic", "-kernel", self.kernel, "-drive", f"file={self.disk},if=none,format=raw,id=hd0",
                "-device", "virtio-blk-device,drive=hd0"]
        p, log = self.run_wrapper(argv)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = slurp(self.out).split("\n")
        self.assertIn("shift=0,sleep=off,rr=record,rrfile=%s/boot-1/rr.bin" % self.rr, got)
        self.assertIn("driver=blkreplay,if=none,image=hd0-direct,id=hd0", got)
        self.assertIn(os.path.join(self.rr, "boot-1", "kernel"), got)
        spec = json.loads(slurp(os.path.join(self.rr, "boot-1", "spec.json")))
        self.assertEqual(spec["isa"], "riscv64")
        self.assertEqual(slurp(os.path.join(self.rr, "boot-1", "kernel"), "rb"), b"ELF")
        self.assertEqual(slurp(os.path.join(self.rr, "boot-1", "disk-0.img"), "rb"), b"DISK")
        # The console copy survives the row deleting its log.
        os.remove(log)
        for _ in range(100):
            if os.path.exists(os.path.join(self.rr, "boot-1", "console.log")):
                break
            subprocess.call(["sleep", "0.1"])
        self.assertTrue(os.path.exists(os.path.join(self.rr, "boot-1", "console.log")))

    def test_it_runs_once_behind_the_gates_own_qemu_stand_in(self):
        # ci_check.sh puts tools/gate/qemu_tap.py first on PATH as qemu-system-*; the tap
        # skips its own directory and lands on the wrapper, which must not land on the tap.
        tap = os.path.join(self.tmp, "tap")
        os.mkdir(tap)
        os.symlink(os.path.join(HERE, "../gate/qemu_tap.py"), os.path.join(tap, "qemu-system-riscv64"))
        env = dict(os.environ, PATH=os.pathsep.join([tap, self.wrap, self.real, os.environ["PATH"]]), FAKE_OUT=self.out, RR_DIR=self.rr)
        with open(os.path.join(self.tmp, "c.txt"), "w") as f:
            p = subprocess.run(["qemu-system-riscv64", "-machine", "virt", "-kernel", self.kernel], env=env, stdout=f,
                               stderr=subprocess.PIPE, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.rr, "refused.txt")))
        self.assertEqual([a for a in slurp(self.out).split("\n") if "rr=record" in a].__len__(), 1)

    def test_a_second_boot_gets_its_own_directory(self):
        argv = ["-machine", "virt", "-kernel", self.kernel]
        self.run_wrapper(argv)
        self.run_wrapper(argv)
        self.assertTrue(os.path.isdir(os.path.join(self.rr, "boot-2")))

    def test_refusal_exits_97_with_the_reason_and_starts_nothing(self):
        p, _log = self.run_wrapper(["-machine", "virt", "-kernel", self.kernel, "-netdev", "user,id=n"])
        self.assertEqual(p.returncode, 97)
        self.assertIn("network backend", p.stderr)
        self.assertIn("network backend", slurp(os.path.join(self.rr, "refused.txt")))
        self.assertFalse(os.path.exists(self.out))

    def test_without_rr_dir_it_is_plain_qemu(self):
        p, _log = self.run_wrapper(["-machine", "virt", "-netdev", "user,id=n"], rr=False)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(slurp(self.out).split("\n")[:3], ["-machine", "virt", "-netdev"])

    def test_replay_cmd_rebuilds_the_recorded_command(self):
        self.run_wrapper(["-machine", "virt", "-kernel", self.kernel])
        cmd = subprocess.run([sys.executable, os.path.join(HERE, "rr_qemu.py"), "replay-cmd", self.rr, "--gdb", "--port", "4321"],
                             capture_output=True, text=True, check=True).stdout
        self.assertIn("rr=replay,rrfile=%s/boot-1/rr.bin" % self.rr, cmd)
        self.assertIn("-gdb tcp::4321 -S", cmd)
        self.assertTrue(cmd.startswith("qemu-system-riscv64 "))


class Scripts(unittest.TestCase):
    def sh(self, script, *args, env=None):
        e = {k: v for k, v in os.environ.items() if k not in ("STALL_WATCH", "AZOS_OUT")}
        e.update(env or {})
        return subprocess.run(["bash", os.path.join(HERE, script)] + list(args), capture_output=True, text=True, env=e)

    def test_rr_row_argument_checks(self):
        self.assertEqual(self.sh("rr_row.sh").returncode, 2)
        self.assertEqual(self.sh("rr_row.sh", "x", "--runs", "0").returncode, 2)
        self.assertEqual(self.sh("rr_row.sh", "x", "--runs", "abc").returncode, 2)
        self.assertEqual(self.sh("rr_row.sh", "x", "--bogus").returncode, 2)
        self.assertEqual(self.sh("rr_row.sh", "a", "b").returncode, 2)
        p = self.sh("rr_row.sh", "ktest (rv)", env={"AZOS_OUT": ""})
        self.assertEqual(p.returncode, 2)
        self.assertIn("AZOS_OUT", p.stderr)

    def test_rr_row_refuses_the_stall_watcher_and_unknown_rows(self):
        p = self.sh("rr_row.sh", "ktest (rv)", env={"STALL_WATCH": "x", "AZOS_OUT": "/nonexistent"})
        self.assertEqual(p.returncode, 3)
        self.assertIn("STALL_WATCH", p.stderr)
        p = self.sh("rr_row.sh", "no such gate row", env={"AZOS_OUT": "/nonexistent"})
        self.assertEqual(p.returncode, 2)
        self.assertIn("no gate row labelled", p.stderr)

    def test_rr_replay_argument_checks(self):
        self.assertEqual(self.sh("rr_replay.sh").returncode, 2)
        with tempfile.TemporaryDirectory() as d:
            p = self.sh("rr_replay.sh", d)
            self.assertEqual(p.returncode, 2)
            self.assertIn("not a recording", p.stderr)
            self.assertEqual(self.sh("rr_replay.sh", d, "--boot", "x").returncode, 2)
            self.assertEqual(self.sh("rr_replay.sh", d, "--nope").returncode, 2)


if __name__ == "__main__":
    unittest.main()
