#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_debug.py — host tests of `make debug`'s tools (debug_script.py, symbolize_bt.py).

The symbolizer runs against a small aarch64 ELF with DWARF that the test
builds (clang for the object, rust-lld for the link); the script generator
against fake debuggers on a private PATH and against a stub of lldb's module.
No QEMU: the gate's `debug:` rows attach real debuggers to real kernels.

Run with:
    python3 tools/dev/test_debug.py
"""

import contextlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401

import debug_row  # noqa: E402
import debug_script  # noqa: E402
import symbolize_bt  # noqa: E402

# The unit under test is "the call is the last instruction of the function":
# `fail`'s return address is the first byte of the function that follows it.
SOURCE = """\
void die(void) __attribute__((noreturn));
int leaf(int x) { return x * 3; }
int top(int x) {
    return leaf(x) + 1;
}
void fail(void) { die(); }
void die(void) { for (;;) {} }
void _start(void) { volatile int r = top(2); (void)r; fail(); }
"""
LINK = 0x40000000


def rust_lld():
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True).stdout.strip()
    for d, _dirs, names in os.walk(sysroot):
        if "rust-lld" in names:
            return os.path.join(d, "rust-lld")
    return None


def build_elf(tmp):
    src, obj, elf = (os.path.join(tmp, n) for n in ("t.c", "t.o", "t.elf"))
    write(src, SOURCE)
    subprocess.run(["clang", "--target=aarch64-none-elf", "-g", "-O0", "-ffreestanding", "-fno-pic", "-c", src, "-o", obj],
                   check=True, capture_output=True)
    subprocess.run([rust_lld(), "-flavor", "gnu", "-Ttext=0x%x" % LINK, "--defsym=_text_start=0x%x" % LINK,
                    "-e", "_start", "-o", elf, obj], check=True, capture_output=True)
    return elf


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def read(path):
    with open(path) as f:
        return f.read()


def symbol_addr(elf, name):
    return symbolize_bt.elf_symbol(elf, name)


def run_tool(elf, log_text, *extra):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        with tempfile.NamedTemporaryFile("w", suffix=".log") as log:
            log.write(log_text)
            log.flush()
            rc = symbolize_bt.main([elf, log.name, *extra])
    return rc, out.getvalue(), err.getvalue()


@unittest.skipUnless(shutil.which("clang") and symbolize_bt.find_addr2line() and subprocess.run(
    ["rustc", "--print", "sysroot"], capture_output=True).returncode == 0 and rust_lld(),
    "needs clang, rust-lld and an addr2line")
class Symbolize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.elf = build_elf(cls.tmp)
        cls.leaf, cls.top = symbol_addr(cls.elf, "leaf"), symbol_addr(cls.elf, "top")
        cls.fail, cls.die = symbol_addr(cls.elf, "fail"), symbol_addr(cls.elf, "die")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def line(self, *addrs, stop="root"):
        return "[PANIC] backtrace:" + "".join(" 0x%x" % a for a in addrs) + " (stopped: %s)\n" % stop

    def test_function_file_and_line_of_each_frame(self):
        rc, out, _ = run_tool(self.elf, self.line(self.leaf + 8, self.top + 24))
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"#0 +0x[0-9a-f]+ +leaf at .*t\.c:2")
        self.assertRegex(out, r"#1 +0x[0-9a-f]+ +top at .*t\.c:4")
        self.assertIn("stopped: root", out)

    def test_the_slide_comes_from_the_kaslr_line(self):
        slide = 0x200000
        log = "[KASLR] image slid to 0x%x, 9 bits, seed: yes - dt -\r\n" % (LINK + slide)
        log += self.line(self.leaf + 8 + slide, self.top + 24 + slide)
        rc, out, _ = run_tool(self.elf, log)
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"leaf at .*t\.c:2")
        self.assertIn("slide 0x200000", out)

    def test_canary_slid_log_without_its_slide_is_refused(self):
        slide = 0x200000
        rc, out, err = run_tool(self.elf, self.line(self.leaf + 8 + slide))
        self.assertEqual(rc, 1)
        self.assertIn("??", out)
        self.assertIn("--slide", err)

    def test_slide_option_names_the_slide_a_release_log_lacks(self):
        slide = 0x400000
        log = "[KASLR] image slid, 9 bits, seed: yes - dt -\n" + self.line(self.leaf + 8 + slide)
        rc, out, _ = run_tool(self.elf, log, "--slide", hex(slide))
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"leaf at .*t\.c:2")

    def test_a_return_address_is_looked_up_inside_the_call(self):
        # `fail` ends in the call to `die`: its return address is `die`'s first byte.
        rc, out, _ = run_tool(self.elf, self.line(self.die))
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"fail at ")
        self.assertNotRegex(out, r"die at ")

    def test_a_log_without_a_backtrace_fails(self):
        rc, _, err = run_tool(self.elf, "[PANIC] something else\n")
        self.assertEqual(rc, 1)
        self.assertIn("no '[PANIC] backtrace:'", err)

    def test_elf_symbol_reads_the_symtab(self):
        self.assertEqual(symbol_addr(self.elf, "_text_start"), LINK)
        self.assertIsNone(symbol_addr(self.elf, "no_such_symbol"))

    def test_elf_bytes_reads_the_loaded_segment(self):
        head = debug_row.elf_bytes(self.elf, self.leaf, 8)
        self.assertEqual(len(head), 8)
        self.assertEqual(head[:4] + debug_row.elf_bytes(self.elf, self.leaf + 4, 4), head)
        self.assertNotEqual(head, debug_row.elf_bytes(self.elf, self.top, 8))
        with self.assertRaises(ValueError):
            debug_row.elf_bytes(self.elf, LINK - 0x1000, 8)

    def test_a_non_elf_file_is_a_usage_error(self):
        bogus = os.path.join(self.tmp, "bogus")
        write(bogus, "not an ELF")
        rc, _, err = run_tool(bogus, self.line(1))
        self.assertEqual(rc, 2)
        self.assertIn("not an ELF64", err)


GDB_DUMP = ("0xffffffef71076244 <kernel::kernel_main>:\t0x41\t0x71\t0x86\t0xf7\n"
            "0xffffffef71076248 <kernel::kernel_main+4>:\t0xa2\t0xf3\t0xa6\t0xef\n")
LLDB_DUMP = ("0xffffff8001076244: 0x41 0x71 0x86 0xf7 0xa2 0xf3 0xa6 0xef\n")
SYM = "kernel::kernel_main in section .text\n"
BYTES = bytes([0x41, 0x71, 0x86, 0xf7, 0xa2, 0xf3, 0xa6, 0xef])


class RowJudge(unittest.TestCase):
    def test_a_gdb_dump_is_read_with_its_address(self):
        self.assertEqual(debug_row.read_dump("noise\n" + GDB_DUMP), (0xffffffef71076244, BYTES))

    def test_an_lldb_dump_is_read_with_its_address(self):
        self.assertEqual(debug_row.read_dump(LLDB_DUMP), (0xffffff8001076244, BYTES))

    def test_the_read_must_be_at_the_address_with_the_bytes(self):
        out = "kernel::kernel_main in section .text\n" + GDB_DUMP
        self.assertIsNone(debug_row.judge_read(out, 0xffffffef71076244, BYTES))
        out = "      Summary: kernel`kernel_main\n" + LLDB_DUMP
        self.assertIsNone(debug_row.judge_read(out, 0xffffff8001076244, BYTES))

    def test_canary_another_symbol_at_the_address_is_refused(self):
        out = "kernel::tasks::system::idle_task + 206 in section .text\n" + GDB_DUMP
        self.assertIn("names no kernel_main", debug_row.judge_read(out, 0xffffffef71076244, BYTES))
        self.assertIn("names no kernel_main", debug_row.judge_read("kernel::kernel_main_hook + 4\n" + GDB_DUMP, 0xffffffef71076244, BYTES))

    def test_canary_a_symbol_at_another_address_is_refused(self):
        self.assertIn("expected", debug_row.judge_read(SYM + GDB_DUMP, 0xffffffef71276244, BYTES))

    def test_canary_other_bytes_are_refused(self):
        self.assertIn("the ELF", debug_row.judge_read(SYM + GDB_DUMP, 0xffffffef71076244, BYTES[::-1]))

    def test_canary_an_unreadable_address_is_refused(self):
        self.assertIn("no memory dump", debug_row.judge_read(SYM + "Cannot access memory at address 0xffffffef71276244\n", 1, BYTES))

    def test_pc_is_read_from_both_debuggers(self):
        self.assertEqual(debug_row.PC.search("pc             0x1000\t0x1000").group(1), "0x1000")
        self.assertEqual(debug_row.PC.search("      pc = 0x0000000040000000").group(1), "0x0000000040000000")
        self.assertEqual(debug_row.PC.search("     rip = 0x000000000000fff0").group(1), "0x000000000000fff0")
        self.assertIsNone(debug_row.PC.search("The program has no registers now."))

    def test_the_commands_are_each_debuggers_own(self):
        self.assertEqual(debug_row.commands("riscv64-elf-gdb", 0x1000),
                         ("info registers pc", "info symbol 0x1000", "x/32xb 0x1000"))
        self.assertEqual(debug_row.commands("lldb", 0x1000),
                         ("register read pc", "image lookup -a 0x1000", "memory read -s1 -c32 -fx 0x1000"))

    def test_the_prompt_follows_the_console_program(self):
        self.assertEqual(debug_row.prompt_of("CONFIG_CONSOLE_PROGRAM_SH=y\n"), "azos$ ")
        self.assertEqual(debug_row.prompt_of("CONFIG_CONSOLE_PROGRAM_NONE=y\n"), "generic> ")
        self.assertIsNone(debug_row.prompt_of("CONFIG_CONSOLE_PROGRAM_BUSYBOX_SH=y\n"))
        self.assertIsNone(debug_row.prompt_of("# CONFIG_CONSOLE_PROGRAM_SH is not set\n"))

    def test_the_script_names_its_elf(self):
        tmp = tempfile.mkdtemp()
        try:
            cmd, gdb = debug_script.write_script("riscv64", "/x/kernel", 1, tmp, "/b/riscv64-elf-gdb")
            self.assertEqual(debug_row.script_elf(gdb), "/x/kernel")
            cmd, py = debug_script.write_script("aarch64", "/x/kernel", 1, tmp, "/b/lldb")
            self.assertEqual(debug_row.script_elf(py), "/x/kernel")
        finally:
            shutil.rmtree(tmp)


class Script(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        self.elf = os.path.join(self.tmp, "kernel")
        write(self.elf, "elf")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def install(self, *names):
        for n in names:
            p = os.path.join(self.bin, n)
            write(p, "#!/bin/sh\n")
            os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)

    def test_the_debugger_is_chosen_per_isa(self):
        self.install("riscv64-elf-gdb", "lldb")
        self.assertEqual(os.path.basename(debug_script.pick_debugger("riscv64", self.bin)), "riscv64-elf-gdb")
        self.assertEqual(os.path.basename(debug_script.pick_debugger("aarch64", self.bin)), "lldb")
        self.assertEqual(os.path.basename(debug_script.pick_debugger("x86_64", self.bin)), "lldb")

    def test_a_gdb_built_for_the_isa_wins_over_lldb(self):
        self.install("aarch64-elf-gdb", "lldb")
        self.assertEqual(os.path.basename(debug_script.pick_debugger("aarch64", self.bin)), "aarch64-elf-gdb")

    def test_canary_riscv64_is_never_served_by_lldb(self):
        self.install("lldb")
        self.assertIsNone(debug_script.pick_debugger("riscv64", self.bin))

    def test_gdb_script_loads_the_elf_connects_and_defines_slide(self):
        gdb = os.path.join(self.bin, "riscv64-elf-gdb")
        cmd, script = debug_script.write_script("riscv64", self.elf, 4321, self.tmp, gdb)
        text = read(script)
        self.assertEqual(cmd, [gdb, "-q", "-x", script])
        self.assertIn("file %s\n" % self.elf, text)
        self.assertIn("target remote 127.0.0.1:4321\n", text)
        self.assertIn("define azos-slide", text)
        self.assertIn("set $azos_slide = (unsigned long)$arg0 - (unsigned long)&_text_start\n", text)
        self.assertIn("symbol-file %s -o $azos_slide\n" % self.elf, text)

    def test_lldb_module_compiles_and_slides_by_base_minus_link(self):
        lldb = os.path.join(self.bin, "lldb")
        cmd, script = debug_script.write_script("aarch64", self.elf, 4321, self.tmp, lldb)
        self.assertEqual(cmd, [lldb, "-o", "command script import " + script])
        self.assertTrue(os.path.basename(script).isidentifier() or script.endswith("debug_aarch64.py"))
        text = read(script)
        calls = []

        class Err:
            def Fail(self): return False

        class Sym:
            def GetStartAddress(self): return types.SimpleNamespace(GetFileAddress=lambda: 0xffffffff81000000)

        class Target:
            def FindSymbols(self, name):
                ctx = types.SimpleNamespace(GetSymbol=lambda: Sym())
                return types.SimpleNamespace(GetSize=lambda: 1, GetContextAtIndex=lambda i: ctx)
            def GetModuleAtIndex(self, i): return "module"
            def SetModuleLoadAddress(self, mod, slide):
                calls.append((mod, slide))
                return Err()

        dbg = types.SimpleNamespace(GetSelectedTarget=lambda: Target(), HandleCommand=lambda c: calls.append(c))
        ns = {"__name__": "debug_aarch64"}
        sys.modules["lldb"] = types.ModuleType("lldb")
        try:
            exec(compile(text, script, "exec"), ns)
        finally:
            del sys.modules["lldb"]
        ns["__lldb_init_module"](dbg, {})
        self.assertEqual(calls[0], "target create " + self.elf)
        self.assertIn("debug_aarch64.azos_slide azos-slide", calls[1])
        self.assertEqual(calls[2], "gdb-remote 127.0.0.1:4321")
        calls.clear()
        res = types.SimpleNamespace(SetError=lambda m: calls.append(m))
        ns["azos_slide"](dbg, "0xffffffff81200000", res, {})
        self.assertEqual(calls, [("module", 0x200000)])
        calls.clear()
        ns["azos_slide"](dbg, "0xffffffff80e00000", res, {})
        self.assertEqual(calls, [("module", -0x200000)])

    def test_batch_command_appends_the_commands(self):
        self.assertEqual(debug_script.batch_command(["g", "-q", "-x", "s"], ["a", "b"]),
                         ["g", "-q", "-x", "s", "-batch", "-ex", "a", "-ex", "b"])
        self.assertEqual(debug_script.batch_command(["/x/lldb", "-o", "i"], ["a"]), ["/x/lldb", "-o", "i", "-b", "-o", "a"])

    def test_main_prints_the_command_and_refuses_without_an_elf(self):
        self.install("riscv64-elf-gdb")
        out, err = io.StringIO(), io.StringIO()
        old = os.environ["PATH"]
        os.environ["PATH"] = self.bin
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = debug_script.main(["riscv64", self.elf, "--out-dir", self.tmp])
                missing = debug_script.main(["riscv64", os.path.join(self.tmp, "nope")])
        finally:
            os.environ["PATH"] = old
        self.assertEqual(rc, 0)
        self.assertTrue(out.getvalue().startswith(os.path.join(self.bin, "riscv64-elf-gdb") + " -q -x "))
        self.assertEqual(missing, 1)
        self.assertIn("make build first", err.getvalue())

    def test_main_names_the_candidates_when_none_is_installed(self):
        err = io.StringIO()
        old = os.environ["PATH"]
        os.environ["PATH"] = self.bin
        try:
            with contextlib.redirect_stderr(err):
                rc = debug_script.main(["x86_64", self.elf])
        finally:
            os.environ["PATH"] = old
        self.assertEqual(rc, 1)
        self.assertIn("x86_64-elf-gdb", err.getvalue())


if __name__ == "__main__":
    unittest.main()
