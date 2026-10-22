#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_farm.py — host tests of the board farm (tools/farm/).

No board, no relay, no network beyond loopback: the TAP parser against
synthetic logs, the relay's dry-run backend and its exec backend with a fake
runner, the dnsmasq configuration, the TFTP client against tools/tftp_serve.py,
the ELF registry count against a hand-made ELF, and the whole run against a
fake board: a pseudo-terminal whose far end prints a canned boot log when the
dry-run relay switches the power on.

Run with:
    python3 tools/test_farm.py
"""

import io
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

TOOLS = Path(__file__).parent.resolve()
sys.path.insert(0, str(TOOLS / "farm"))
sys.path.insert(0, str(TOOLS))

import farm  # noqa: E402
import farm_config  # noqa: E402
import farm_elf  # noqa: E402
import farm_net  # noqa: E402
import farm_pstore  # noqa: E402
import farm_relay  # noqa: E402
import farm_serial  # noqa: E402
import farm_tap  # noqa: E402
import tftp_serve  # noqa: E402

BOOT_NOISE = ["U-Boot SPL 2021.10", "OpenSBI v1.2", "[ISA] baseline=rv64gc exts=none",
              "[MM] ASID: hw 16 bits, ASID_BITS 16, user ASIDs 1..=65535 (riscv64)"]


def tap_lines(n=3, not_ok=(), summary=True, bail_after=None, noise=True):
    """The runner's output for n tests, as the console shows it."""
    out = list(BOOT_NOISE) if noise else []
    out += [f"1..{n}", "# ktest phase early: 2 tests, boot hart, before the scheduler (riscv64)"]
    for k in range(1, n + 1):
        out.append(f"# ktest {k} t{k}")
        out.append(f"not ok {k} - t{k} # reason" if k in not_ok else f"ok {k} - t{k}")
    if summary:
        out.append(f"# ktest: {n} tests, {n - len(not_ok)} passed, {len(not_ok)} failed (riscv64)")
    if bail_after:
        out.append(bail_after)
    return out


def judge(lines, expected_plan=None):
    tap = farm_tap.Tap()
    for ln in lines:
        tap.feed(ln)
    return tap.verdict(expected_plan)


class TapTests(unittest.TestCase):
    def test_clean_run_passes(self):
        self.assertTrue(judge(tap_lines()).ok)

    def test_clean_run_with_the_expected_plan_passes(self):
        self.assertTrue(judge(tap_lines(), expected_plan=3).ok)

    def test_plan_that_is_not_the_images_registry_fails(self):
        v = judge(tap_lines(), expected_plan=4)
        self.assertFalse(v.ok)
        self.assertIn("holds 4", v.why)

    def test_a_not_ok_fails_and_is_named(self):
        v = judge(tap_lines(not_ok=(2,)))
        self.assertFalse(v.ok)
        self.assertIn("t2", v.why)

    def test_no_plan_fails(self):
        v = judge(BOOT_NOISE)
        self.assertFalse(v.ok)
        self.assertIn("no TAP plan", v.why)

    def test_missing_summary_fails(self):
        v = judge(tap_lines(summary=False))
        self.assertFalse(v.ok)
        self.assertIn("no summary", v.why)

    def test_a_result_reported_twice_fails(self):
        lines = tap_lines()
        lines.insert(lines.index("ok 2 - t2") + 1, "ok 2 - t2")
        v = judge(lines)
        self.assertFalse(v.ok)
        self.assertIn("test 2 reported 2 times", v.why)

    def test_a_missing_result_fails_and_names_the_test_that_was_running(self):
        lines = [ln for ln in tap_lines(summary=False) if ln != "ok 3 - t3"]
        v = judge(lines)
        self.assertFalse(v.ok)
        self.assertIn("test 3 reported 0 times", v.why)
        self.assertIn("3 t3", v.why)

    def test_bail_out_fails(self):
        lines = tap_lines(n=3, summary=False)[:-1]
        lines.append("Bail out! ktest: t3 panicked; tests 4.. did not run (riscv64)")
        v = judge(lines)
        self.assertFalse(v.ok)
        self.assertIn("bailed out", v.why)

    def test_bail_out_right_after_the_summary_still_fails(self):
        v = judge(tap_lines(bail_after="Bail out! lockdep: 1 violation(s) outside any test (riscv64)"))
        self.assertFalse(v.ok)
        self.assertIn("lockdep", v.why)

    def test_a_second_plan_means_the_board_restarted(self):
        lines = tap_lines(n=3, summary=False)[:6] + tap_lines()
        v = judge(lines)
        self.assertFalse(v.ok)
        self.assertIn("restarted", v.why)

    def test_a_summary_that_disagrees_with_the_plan_fails(self):
        lines = tap_lines()
        lines[-1] = "# ktest: 3 tests, 2 passed, 1 failed (riscv64)"
        self.assertFalse(judge(lines).ok)

    def test_lines_that_only_contain_tap_are_not_tap(self):
        # A kernel log line with a TAP-looking tail, or indented, is noise.
        lines = tap_lines(summary=False)
        lines.insert(4, "[KLOG] 1..99")
        lines.insert(5, "  not ok 1 - t1")
        lines.insert(6, "[KLOG] ok 2 - x")
        lines.append("# ktest: 3 tests, 3 passed, 0 failed (riscv64)")
        self.assertTrue(judge(lines).ok)

    def test_facts_are_collected_not_asserted(self):
        tap = farm_tap.Tap()
        for ln in tap_lines():
            tap.feed(ln)
        self.assertTrue(tap.facts["isa"][0].startswith("[ISA] baseline"))
        self.assertIn("ASID: hw 16 bits", tap.facts["asid"][0])

    def test_feed_returns_true_only_at_a_bail_out(self):
        tap = farm_tap.Tap()
        results = [tap.feed(ln) for ln in tap_lines()]
        self.assertFalse(any(results))
        self.assertTrue(tap.feed("Bail out! x"))


class RelayTests(unittest.TestCase):
    def test_dry_run_records_a_cycle_in_order(self):
        relay = farm_relay.DryRunRelay()
        waits = []
        relay.cycle(3.0, sleep=waits.append)
        self.assertEqual(relay.events, ["off", "on"])
        self.assertEqual(waits, [3.0])

    def test_dry_run_tells_its_observer(self):
        seen = []
        relay = farm_relay.DryRunRelay(on_event=seen.append)
        relay.on()
        relay.off()
        self.assertEqual(seen, ["on", "off"])

    def test_exec_runs_the_configured_commands_without_a_shell(self):
        calls = []

        class R:
            returncode = 0
            stdout = b""

        def runner(argv, **kw):
            calls.append(argv)
            return R()

        relay = farm_relay.ExecRelay("usbrelay HW348_1=1", "usbrelay 'HW 348_1=0'", runner=runner)
        relay.cycle(0, sleep=lambda s: None)
        self.assertEqual(calls, [["usbrelay", "HW 348_1=0"], ["usbrelay", "HW348_1=1"]])

    def test_exec_failure_is_a_relay_error_naming_the_command(self):
        class R:
            returncode = 2
            stdout = b"no such device"

        relay = farm_relay.ExecRelay("on-cmd", "off-cmd", runner=lambda argv, **kw: R())
        with self.assertRaises(farm_relay.RelayError) as cm:
            relay.on()
        self.assertIn("on-cmd", str(cm.exception))
        self.assertIn("no such device", str(cm.exception))

    def test_exec_missing_program_is_a_relay_error(self):
        relay = farm_relay.ExecRelay("/nonexistent/relay-tool on", "/nonexistent/relay-tool off")
        with self.assertRaises(farm_relay.RelayError):
            relay.off()


def board_ini(tmp, **over):
    """A boards.ini [vf2] entry; returns its path."""
    keys = {"serial": "/dev/null", "relay": "dry-run", "mac": "6C:CF:39:00:00:01",
            "board_ip": "192.168.50.20", "server_ip": "192.168.50.1", "interface": "en7",
            "tftp_root": str(Path(tmp) / "tftp"), "verify_tftp": "no", "power_off_s": "0.01",
            "log_dir": str(Path(tmp) / "logs"), "boot_deadline_s": "5", "ktest_deadline_s": "5",
            "pstore_deadline_s": "5"}
    keys.update(over)
    path = Path(tmp) / "boards.ini"
    path.write_text("[vf2]\n" + "".join(f"{k} = {v}\n" for k, v in keys.items() if v is not None))
    (Path(tmp) / "tftp").mkdir(exist_ok=True)
    return str(path)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_no_file_is_no_board(self):
        with self.assertRaises(farm_config.NoBoard):
            farm_config.load("vf2", str(Path(self.tmp.name) / "absent.ini"))

    def test_no_section_is_no_board(self):
        path = board_ini(self.tmp.name)
        with self.assertRaises(farm_config.NoBoard):
            farm_config.load("k1", path)

    def test_a_complete_entry_loads(self):
        b = farm_config.load("vf2", board_ini(self.tmp.name))
        self.assertEqual((b.baud, b.mac, b.kernel_name, b.tftp_port), (115200, "6c:cf:39:00:00:01", "kernel.bin", 69))

    def test_a_missing_required_key_is_a_config_error(self):
        with self.assertRaises(farm_config.ConfigError) as cm:
            farm_config.load("vf2", board_ini(self.tmp.name, serial=None))
        self.assertIn("serial", str(cm.exception))

    def test_exec_relay_needs_its_commands(self):
        with self.assertRaises(farm_config.ConfigError):
            farm_config.load("vf2", board_ini(self.tmp.name, relay="exec"))

    def test_unknown_relay_backend_is_refused(self):
        with self.assertRaises(farm_config.ConfigError):
            farm_config.load("vf2", board_ini(self.tmp.name, relay="magic"))

    def test_the_example_entry_loads_once_its_placeholders_are_filled(self):
        text = (TOOLS / "farm" / "boards.ini.example").read_text()
        path = Path(self.tmp.name) / "example.ini"
        path.write_text(text)
        b = farm_config.load("vf2", str(path))
        self.assertEqual(b.isa, "riscv64")


class NetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.board = farm_config.load("vf2", board_ini(self.tmp.name))

    def test_dnsmasq_serves_this_board_and_nobody_else(self):
        conf = farm_net.dnsmasq_conf(self.board)
        for want in ("port=0", "interface=en7", "bind-interfaces",
                     "dhcp-range=192.168.50.20,static,255.255.255.0",
                     "dhcp-host=6c:cf:39:00:00:01,192.168.50.20,vf2", "dhcp-ignore=tag:!known",
                     "dhcp-boot=kernel.bin,vf2,192.168.50.1", "enable-tftp",
                     f"tftp-root={self.tmp.name}/tftp"):
            self.assertIn(want, conf.splitlines())

    def test_no_interface_no_dhcp_server(self):
        board = farm_config.load("vf2", board_ini(self.tmp.name, interface=""))
        with self.assertRaises(farm_config.ConfigError):
            farm_net.dnsmasq_conf(board)

    def test_stage_publishes_the_kernel_under_the_boot_file_name(self):
        kernel = Path(self.tmp.name) / "k.bin"
        kernel.write_bytes(b"\x01" * 1000)
        dst = farm_net.stage(self.board, str(kernel))
        self.assertEqual(Path(dst).read_bytes(), kernel.read_bytes())
        self.assertEqual(os.path.basename(dst), "kernel.bin")
        self.assertFalse(os.path.exists(dst + ".tmp"))

    def test_stage_into_a_missing_root_is_a_config_error(self):
        board = farm_config.load("vf2", board_ini(self.tmp.name, tftp_root=str(Path(self.tmp.name) / "nope")))
        with self.assertRaises(farm_config.ConfigError):
            farm_net.stage(board, __file__)

    def _serve(self, root):
        listen = tftp_serve.socket.socket(tftp_serve.socket.AF_INET, tftp_serve.socket.SOCK_DGRAM)
        listen.bind(("127.0.0.1", 0))
        listen.settimeout(10)

        def loop():
            try:
                pkt, addr = listen.recvfrom(600)
            except OSError:
                return
            name, mode = tftp_serve.parse_rrq(pkt)
            tftp_serve.handle_transfer(addr, name, mode, root)

        threading.Thread(target=loop, daemon=True).start()
        self.addCleanup(listen.close)
        return listen.getsockname()[1]

    def test_tftp_get_reads_what_tools_tftp_serve_serves(self):
        root = Path(self.tmp.name) / "tftp"
        # Exactly 3 blocks: the final empty DATA block is part of the protocol.
        payload = bytes(range(256)) * 6
        (root / "kernel.bin").write_bytes(payload)
        port = self._serve(str(root))
        self.assertEqual(farm_net.tftp_get("127.0.0.1", port, "kernel.bin"), payload)

    def test_tftp_get_of_a_missing_file_is_an_error_from_the_server(self):
        port = self._serve(str(Path(self.tmp.name) / "tftp"))
        with self.assertRaises(OSError) as cm:
            farm_net.tftp_get("127.0.0.1", port, "absent.bin")
        self.assertIn("no such file", str(cm.exception))

    def test_verify_reports_a_server_that_serves_something_else(self):
        other = Path(self.tmp.name) / "other"
        other.mkdir()
        (other / "kernel.bin").write_bytes(b"old kernel")
        (Path(self.tmp.name) / "tftp" / "kernel.bin").write_bytes(b"the staged kernel")
        port = self._serve(str(other))
        board = farm_config.load("vf2", board_ini(self.tmp.name, server_ip="127.0.0.1", tftp_port=str(port)))
        with self.assertRaises(OSError) as cm:
            farm_net.verify(board)
        self.assertIn("another TFTP root", str(cm.exception))


def make_elf(path, symbols):
    """A minimal ELF64-LE with a symbol table: header, .symtab, .strtab, shstrtab."""
    strtab = b"\0" + b"".join(n.encode() + b"\0" for n in symbols)
    offsets, pos = {}, 1
    for n in symbols:
        offsets[n] = pos
        pos += len(n) + 1
    symtab = b"\0" * 24 + b"".join(
        struct.pack("<IBBHQQ", offsets[n], 0, 0, 1, v, 0) for n, v in symbols.items())
    shstr = b"\0.symtab\0.strtab\0"
    body_off = 64
    symtab_off = body_off
    strtab_off = symtab_off + len(symtab)
    shstr_off = strtab_off + len(strtab)
    sh_off = shstr_off + len(shstr)
    sections = [
        (0,) * 10,
        (1, 2, 0, 0, symtab_off, len(symtab), 2, 0, 8, 24),
        (9, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0),
        (17 - 8, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0),
    ]
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 243, 1, 0, 0, sh_off, 0, 64, 0, 0, 64, len(sections), 3)
    data = ehdr + symtab + strtab + shstr + b"".join(struct.pack("<IIQQQQIIQQ", *s) for s in sections)
    Path(path).write_bytes(data)


class ElfTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "kernel.elf")

    def test_registry_count_is_the_span_over_the_entry_size(self):
        make_elf(self.path, {"__start_azos_ktest": 0x4000_0000, "__stop_azos_ktest": 0x4000_0000 + 95 * 32, "main": 1})
        self.assertEqual(farm_elf.registry_count(self.path), 95)

    def test_an_image_without_the_registry_is_named(self):
        make_elf(self.path, {"main": 1})
        with self.assertRaises(farm_elf.ElfError) as cm:
            farm_elf.registry_count(self.path)
        self.assertIn("ktest feature", str(cm.exception))

    def test_a_span_that_is_not_whole_entries_is_refused(self):
        make_elf(self.path, {"__start_azos_ktest": 0x1000, "__stop_azos_ktest": 0x1000 + 33})
        with self.assertRaises(farm_elf.ElfError):
            farm_elf.registry_count(self.path)

    def test_not_an_elf_is_refused(self):
        Path(self.path).write_bytes(b"MZ" + b"\0" * 100)
        with self.assertRaises(farm_elf.ElfError):
            farm_elf.registry_count(self.path)


class FakeBoard:
    """The far end of a pseudo-terminal: prints `script` (lines) when told the
    power came on, a line at a time."""

    def __init__(self, script, gap_s=0.0):
        self.master, self.slave = os.openpty()
        self.path = os.ttyname(self.slave)
        self.script = script
        self.gap_s = gap_s
        self.powered = []

    def on_event(self, name):
        self.powered.append(name)
        if name != "on":
            return

        def play():
            for ln in self.script:
                os.write(self.master, (ln + "\r\n").encode())
                if self.gap_s:
                    time.sleep(self.gap_s)

        threading.Thread(target=play, daemon=True).start()

    def close(self):
        os.close(self.master)
        os.close(self.slave)


class RunBase(unittest.TestCase):
    """farm.run_scenario against a fake board (the tests are in RunTests and RunPstoreTests)."""

    def setUp(self):
        saved = farm.SUMMARY_GRACE_S
        farm.SUMMARY_GRACE_S = 0.3
        self.addCleanup(setattr, farm, "SUMMARY_GRACE_S", saved)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.kernel = Path(self.tmp.name) / "kernel.bin"
        self.kernel.write_bytes(b"\x13" * 700)

    def go(self, script, scenario="ktest", expected_plan=None, **over):
        fake = FakeBoard(script)
        self.addCleanup(fake.close)
        board = farm_config.load("vf2", board_ini(self.tmp.name, serial=fake.path, **over))
        relay = farm_relay.DryRunRelay(on_event=fake.on_event)
        out = io.StringIO()
        with redirect_stdout(out):
            rc = farm.run_scenario(board, scenario, str(self.kernel), relay, expected_plan)
        return rc, out.getvalue(), relay, board


class RunTests(RunBase):
    def test_a_clean_ktest_boot_exits_0_and_cycles_the_power(self):
        rc, out, relay, board = self.go(tap_lines(n=5), expected_plan=5)
        self.assertEqual(rc, farm.EXIT_OK, out)
        # off, on for the cycle, then off for good.
        self.assertEqual(relay.events, ["off", "on", "off"])
        self.assertIn("PASS vf2 ktest: 5 tests", out)
        self.assertIn("board: [ISA] baseline", out)
        self.assertEqual((Path(board.tftp_root) / "kernel.bin").read_bytes(), self.kernel.read_bytes())
        logs = list(Path(board.log_dir).glob("vf2-ktest-*.log"))
        self.assertEqual(len(logs), 1)
        self.assertIn(b"ok 5 - t5", logs[0].read_bytes())

    def test_a_not_ok_exits_1(self):
        rc, out, _, _ = self.go(tap_lines(n=3, not_ok=(2,)))
        self.assertEqual(rc, farm.EXIT_RED, out)
        self.assertIn("FAIL vf2 ktest: not ok: t2", out)

    def test_a_board_that_never_prints_a_plan_is_a_farm_error_at_the_boot_deadline(self):
        t0 = time.monotonic()
        rc, out, relay, _ = self.go(BOOT_NOISE, boot_deadline_s="0.6")
        self.assertEqual(rc, farm.EXIT_FARM, out)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertIn("no TAP plan", out)
        self.assertEqual(relay.events[-1], "off")

    def test_a_run_that_stalls_after_the_plan_names_the_test_and_exits_1_at_the_deadline(self):
        stalled = tap_lines(n=4, summary=False)[:-1]      # test 4 started, never reported
        rc, out, _, _ = self.go(stalled, ktest_deadline_s="0.6")
        self.assertEqual(rc, farm.EXIT_RED, out)
        self.assertIn("test 4 reported 0 times", out)
        self.assertIn("4 t4", out)
        self.assertIn("no summary within", out)

    def test_a_bail_out_right_after_the_summary_is_caught_by_the_grace_period(self):
        rc, out, _, _ = self.go(tap_lines(bail_after="Bail out! lockdep: 2 violation(s) outside any test (riscv64)"))
        self.assertEqual(rc, farm.EXIT_RED, out)
        self.assertIn("lockdep", out)

    def test_the_registry_count_of_the_image_is_the_plan_to_expect(self):
        rc, out, _, _ = self.go(tap_lines(n=3), expected_plan=4)
        self.assertEqual(rc, farm.EXIT_RED, out)
        self.assertIn("holds 4", out)

    def test_a_serial_port_that_is_not_there_is_a_farm_error(self):
        board = farm_config.load("vf2", board_ini(self.tmp.name, serial="/dev/farm-test-no-such-port"))
        relay = farm_relay.DryRunRelay()
        t0 = time.monotonic()
        with redirect_stdout(io.StringIO()):
            rc = farm.run_scenario(board, "ktest", str(self.kernel), relay, None)
        self.assertEqual(rc, farm.EXIT_FARM)
        self.assertLess(time.monotonic() - t0, 2, "refused at once, not at the deadline")
        self.assertEqual(relay.events, ["off"], "the power was never switched on")

    def test_a_relay_that_fails_leaves_a_farm_error(self):
        fake = FakeBoard([])
        self.addCleanup(fake.close)
        board = farm_config.load("vf2", board_ini(self.tmp.name, serial=fake.path))

        class Broken(farm_relay.Relay):
            def on(self):
                raise farm_relay.RelayError("relay on: stuck")

            def off(self):
                raise farm_relay.RelayError("relay off: stuck")

        out = io.StringIO()
        with redirect_stdout(out):
            rc = farm.run_scenario(board, "ktest", str(self.kernel), Broken(), None)
        self.assertEqual(rc, farm.EXIT_FARM)
        self.assertIn("stuck", out.getvalue())


PSTORE_GOOD = [
    "[FS] FAT32 mounted at /fat",
    "[PSTORE] region reserved: 0xfffff000 - 0x100000000 (4 KiB)",
    "[PSTORE] no record from the previous boot",
    "[PSTORE-SMOKE] panicking with the VFS FS lock held",
    "!!! KERNEL PANIC !!!",
    "pstore-smoke: deliberate panic with the VFS FS lock held",
    "[PANIC] pstore record written: 311 bytes",
    "[PANIC] Rebooting in 200 ms...",
    "U-Boot SPL 2021.10",
    "[PSTORE] region reserved: 0xfffff000 - 0x100000000 (4 KiB)",
    "[FS] FAT32 mounted at /fat",
    "[PSTORE] recovered previous panic into /fat/CRASH.LOG: [pstore] [t=3] hart=0 deliberate",
    "[PSTORE-SMOKE] record found this boot (valid); no second panic",
]


class PstoreTests(unittest.TestCase):
    def verdict(self, lines):
        p = farm_pstore.Pstore()
        for ln in lines:
            p.feed(ln)
        return p.verdict(), p

    def test_two_boots_and_a_recovered_record_pass(self):
        v, p = self.verdict(PSTORE_GOOD)
        self.assertTrue(v.ok, v.why)
        self.assertEqual(p.boots(), 2)

    def test_feed_ends_the_capture_at_boot_2s_report(self):
        p = farm_pstore.Pstore()
        ended = [p.feed(ln) for ln in PSTORE_GOOD]
        self.assertEqual(ended.index(True), len(PSTORE_GOOD) - 1)

    def test_a_third_boot_is_a_wrong_counter(self):
        lines = PSTORE_GOOD[:-1] + [PSTORE_GOOD[1]] + PSTORE_GOOD[-1:]
        v, _ = self.verdict(lines)
        self.assertFalse(v.ok)
        self.assertIn("boot counter 3", v.why)

    def test_a_board_without_storage_says_so(self):
        v, _ = self.verdict([ln for ln in PSTORE_GOOD if "FAT32" not in ln])
        self.assertFalse(v.ok)
        self.assertIn("no /fat", v.why)

    def test_a_record_that_was_not_recovered_fails(self):
        lines = [ln for ln in PSTORE_GOOD if "recovered" not in ln]
        v, _ = self.verdict(lines)
        self.assertFalse(v.ok)
        self.assertIn("boot 2 did not print", v.why)

    def test_a_second_panic_banner_fails_and_ends_the_capture(self):
        p = farm_pstore.Pstore()
        ended = [p.feed(ln) for ln in PSTORE_GOOD[:8] + ["!!! KERNEL PANIC !!!"]]
        self.assertTrue(ended[-1])
        self.assertIn("2 panic banners", p.verdict().why)

    def test_boot_1_missing_its_record_fails(self):
        lines = [ln for ln in PSTORE_GOOD if "record written" not in ln]
        v, _ = self.verdict(lines)
        self.assertFalse(v.ok)
        self.assertIn("boot 1 did not print", v.why)


class RunPstoreTests(RunBase):
    def test_the_pstore_scenario_end_to_end(self):
        rc, out, relay, _ = self.go(PSTORE_GOOD, scenario="pstore")
        self.assertEqual(rc, farm.EXIT_OK, out)
        self.assertIn("boot counter: 2", out)

    def test_the_pstore_scenario_on_a_board_without_storage(self):
        rc, out, _, _ = self.go([ln for ln in PSTORE_GOOD if "FAT32" not in ln], scenario="pstore",
                                pstore_deadline_s="0.6")
        self.assertEqual(rc, farm.EXIT_RED, out)
        self.assertIn("no /fat", out)


class CliTests(unittest.TestCase):
    def run_main(self, *argv, env_path):
        old = os.environ.get(farm_config.ENV_PATH)
        os.environ[farm_config.ENV_PATH] = env_path
        out = io.StringIO()
        try:
            with redirect_stdout(out):
                rc = farm.main(list(argv))
        finally:
            if old is None:
                del os.environ[farm_config.ENV_PATH]
            else:
                os.environ[farm_config.ENV_PATH] = old
        return rc, out.getvalue()

    def test_no_board_configured_is_exit_3_for_every_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            absent = str(Path(tmp) / "absent.ini")
            for argv in (["check"], ["net-config"], ["power", "cycle"], ["run", "ktest", "--kernel", "x"]):
                rc, out = self.run_main(*argv, env_path=absent)
                self.assertEqual(rc, farm.EXIT_NO_BOARD, (argv, out))
                self.assertIn("no board configured", out)

    def test_a_broken_entry_is_exit_2_not_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self.run_main("check", env_path=board_ini(tmp, serial=None))
            self.assertEqual(rc, farm.EXIT_FARM, out)

    def test_check_net_config_and_power_on_a_configured_board(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = board_ini(tmp)
            self.assertEqual(self.run_main("check", env_path=path)[0], farm.EXIT_OK)
            rc, out = self.run_main("net-config", env_path=path)
            self.assertEqual(rc, farm.EXIT_OK)
            self.assertIn("dhcp-host=6c:cf:39:00:00:01", out)
            self.assertEqual(self.run_main("power", "cycle", env_path=path)[0], farm.EXIT_OK)

    def test_run_with_an_elf_without_a_registry_is_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf = str(Path(tmp) / "k.elf")
            make_elf(elf, {"main": 1})
            rc, out = self.run_main("run", "ktest", "--kernel", __file__, "--elf", elf, env_path=board_ini(tmp))
            self.assertEqual(rc, farm.EXIT_FARM, out)
            self.assertIn("ktest feature", out)


class SerialTests(unittest.TestCase):
    def test_lines_drop_carriage_returns_and_keep_partial_tails(self):
        lines = farm_serial.Lines()
        got = list(lines.feed(b"ab\r\ncd"))
        got += list(lines.feed(b"ef\r\n\xff\n"))
        self.assertEqual(got, ["ab", "cdef", "�"])
        self.assertEqual(lines.rest(), "")

    def test_a_baud_rate_the_port_cannot_do_is_refused(self):
        with self.assertRaises(farm_serial.SerialError):
            farm_serial.open_raw("/dev/null", 12345)


if __name__ == "__main__":
    unittest.main()
