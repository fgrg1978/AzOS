#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""debug_row.py — the gate's `debug: <isa>` row: `make debug`, then a headless debugger.

    debug_row.py <riscv64|aarch64|x86_64>      (AZOS_OUT set; GATE_PGROUP_DIR, CI_LOG_DIR optional)

In the gate's own output directory it does what the owner types: `make
defconfig ARCH=<isa> PRESET=generic`, `make build`, `make debug`. Then it
runs the debugger `make debug` printed, in batch mode, three times against
that QEMU:

  1. at reset: the gdbstub answers and the CPU is stopped (it reads `pc`);
     detaching lets the kernel boot, to the console program's prompt.
  2. after the boot, with `azos-slide` given the base the console printed: the
     the debugger must name `kernel_main` at the address the ELF and the base
     give, and the target must hold the bytes the ELF has there.
  3. the canary, in the same boot: `azos-slide` given a base one slide step
     off (2 MiB). The same read must then FAIL to match; a judge that passes
     that is a row that looks at nothing.

QEMU is started in a process group of its own and killed with it. Exit
status 0 when all three hold.
"""
import os
import re
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

import debug_script  # noqa: E402
import symbolize_bt  # noqa: E402

FUNCTION = "kernel_main"
SLIDE_STEP = 0x200000
READ_BYTES = 32
PRESET = "generic"
PC = re.compile(r"\b(?:pc|rip)\b\s*(?:=\s*)?(0x[0-9a-fA-F]+)")
SLID = re.compile(r"\[KASLR\] image slid to (0x[0-9a-fA-F]+),")
DUMP = re.compile(r"^\s*(0x[0-9a-fA-F]+)(?: <[^>]*>)?:\s*((?:0x[0-9a-fA-F]{2}\s*)+)$", re.M)


def commands(debugger_name, addr):
    """The debugger's own spelling of: read pc; name the symbol at `addr`; read the bytes at `addr`.
    (lldb's `memory read` evaluates no function name without a process to run an expression in.)"""
    if debugger_name == "lldb":
        return "register read pc", "image lookup -a %#x" % addr, "memory read -s1 -c%d -fx %#x" % (READ_BYTES, addr)
    return "info registers pc", "info symbol %#x" % addr, "x/%dxb %#x" % (READ_BYTES, addr)


def elf_bytes(path, vaddr, n):
    """`n` bytes at virtual address `vaddr` of an ELF64 little-endian file, from its PT_LOAD segments."""
    with open(path, "rb") as f:
        data = f.read()
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        kind, _flags, off, va, _pa, filesz, _memsz, _al = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if kind == 1 and va <= vaddr and vaddr + n <= va + filesz:
            return data[off + vaddr - va:off + vaddr - va + n]
    raise ValueError("%s: no loaded segment holds %#x" % (path, vaddr))


def read_dump(text):
    """(address of the first line, bytes) of a memory dump, or (None, b'')."""
    lines = DUMP.findall(text.replace("\r", ""))
    if not lines:
        return None, b""
    data = bytes(int(b, 16) for _addr, row in lines for b in row.split())
    return int(lines[0][0], 16), data


def judge_read(output, want_addr, want_bytes):
    """None when the debugger names `FUNCTION` at `want_addr` and dumps `want_bytes` from it, else why not."""
    if not re.search(r"\b%s\b" % FUNCTION, DUMP.sub("", output)):
        return "the debugger names no %s at %#x" % (FUNCTION, want_addr)
    addr, got = read_dump(output)
    if addr is None:
        return "no memory dump in the debugger's output: %s" % output.strip().splitlines()[-1:]
    if addr != want_addr:
        return "the symbol is at %#x, expected %#x" % (addr, want_addr)
    if got != want_bytes:
        return "the target holds %s there, the ELF %s" % (got.hex(), want_bytes.hex())
    return None


def prompt_of(config_text):
    """The console program's prompt, from the configuration (as the preset boot rows read it)."""
    program = re.search(r"^CONFIG_CONSOLE_PROGRAM_([A-Z_]+)=y$", config_text, re.M)
    return {"SH": "azos$ ", "NONE": PRESET + "> "}.get(program.group(1) if program else None)


def script_elf(script):
    """The kernel ELF a debugger script was written for."""
    text = read_file(script)
    m = re.search(r"^file (.+)$", text, re.M) or re.search(r"^ELF = '(.+)'$", text, re.M)
    if not m:
        raise ValueError("%s names no ELF" % script)
    return m.group(1)


def read_file(path):
    with open(path) as f:
        return f.read()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Row:
    def __init__(self, isa, repo, out, logs):
        self.isa, self.repo, self.out, self.logs = isa, repo, out, logs
        self.cfg = os.path.join(out, "build", "debug-%s.config" % isa)
        self.env = dict(os.environ, AZOS_OUT=out, KCONFIG_CONFIG=self.cfg)
        self.pg = None

    def make(self, *args, log, background=False):
        cmd = ["make", "-C", self.repo] + list(args)
        with open(log, "wb") as out:
            if not background:
                return subprocess.run(cmd, env=self.env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
            p = subprocess.Popen(cmd, env=self.env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        self.pg = p.pid
        gdir = os.environ.get("GATE_PGROUP_DIR")
        if gdir:
            with open(os.path.join(gdir, str(p.pid)), "w"):
                pass
        return p

    def stop(self):
        if self.pg is None:
            return
        for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 1.0)):
            try:
                os.killpg(self.pg, sig)
            except ProcessLookupError:
                break
            end = time.time() + wait
            while time.time() < end and subprocess.run(["pgrep", "-g", str(self.pg)], capture_output=True).returncode == 0:
                time.sleep(0.1)
        gdir = os.environ.get("GATE_PGROUP_DIR")
        if gdir:
            try:
                os.unlink(os.path.join(gdir, str(self.pg)))
            except FileNotFoundError:
                pass
        self.pg = None

    def debugger(self, cmd, commands_, timeout=120):
        """Run the debugger in batch mode; its output, or None when it did not finish."""
        argv = debug_script.batch_command(cmd, commands_)
        try:
            r = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        return r.stdout + r.stderr

    def console(self, log):
        with open(log, "rb") as f:
            return f.read().decode("latin-1").replace("\r", "").replace("\0", "")

    @staticmethod
    def fail(why):
        print("      " + why)
        return 1

    def run(self):
        fail = self.fail
        os.makedirs(os.path.join(self.out, "build"), exist_ok=True)
        r = self.make("defconfig", "ARCH=" + self.isa, "PRESET=" + PRESET, log=os.path.join(self.logs, "debug-%s.defconfig" % self.isa))
        if r.returncode != 0 or ("CONFIG_ARCH_%s=y" % self.isa.upper()) not in read_file(self.cfg).split("\n"):
            return fail("make defconfig ARCH=%s PRESET=%s did not write a %s configuration" % (self.isa, PRESET, self.isa))
        r = self.make("build", log=os.path.join(self.logs, "debug-%s.build" % self.isa))
        if r.returncode != 0:
            return fail("make build failed, log kept: %s" % os.path.join(self.logs, "debug-%s.build" % self.isa))
        prompt = prompt_of(read_file(self.cfg))
        if prompt is None:
            return fail("the configuration's console program has no prompt this row knows")
        port = free_port()
        log = os.path.join(self.logs, "debug-%s.log" % self.isa)
        self.make("debug", "DEBUG_PORT=%d" % port, log=log, background=True)
        try:
            return self.judge(log, port, prompt, fail)
        finally:
            self.stop()

    def judge(self, log, port, prompt, fail):
        cmd = None
        deadline = time.time() + 120
        while time.time() < deadline and cmd is None:
            m = re.search(r"^\[DEBUG\]   (.+)$", self.console(log), re.M)
            if m:
                cmd = shlex.split(m.group(1))
            else:
                time.sleep(0.5)
        if cmd is None:
            return fail("`make debug` printed no debugger command, log kept: %s" % log)
        script = cmd[cmd.index("-x") + 1] if "-x" in cmd else re.sub(r"^command script import ", "", cmd[cmd.index("-o") + 1])
        if not os.path.isfile(script):
            return fail("`make debug` named %s and did not write it" % script)
        elf = script_elf(script)
        if "127.0.0.1:%d" % port not in read_file(script):
            return fail("the script does not connect to port %d" % port)
        name = os.path.basename(cmd[0])
        pc_cmd = commands(name, 0)[0]

        # 1. at reset
        out = None
        end = time.time() + 60
        while time.time() < end:
            out = self.debugger(cmd, [pc_cmd, "detach"], timeout=60)
            if out and PC.search(out):
                break
            time.sleep(1)
        if not out or not PC.search(out):
            return fail("no debugger session read pc at reset; last output: %s" % (out or "").strip()[-300:])
        print("      at reset: pc=%s (%s)" % (PC.search(out).group(1), os.path.basename(cmd[0])))

        # 2. after the boot
        end = time.time() + int(os.environ.get("DEBUG_ROW_BOOT_LIMIT", "300"))
        while time.time() < end:
            text = self.console(log)
            if prompt in text:
                break
            if re.search(r"panic|FATAL", text, re.I):
                return fail("the kernel crashed after detach, log kept: %s" % log)
            time.sleep(0.5)
        else:
            return fail("no %r after detach within the limit, log kept: %s" % (prompt, log))
        link = symbolize_bt.elf_symbol(elf, "_text_start")
        func = symbolize_bt.elf_symbol(elf, FUNCTION)
        if link is None or func is None:
            return fail("%s has no _text_start or %s" % (elf, FUNCTION))
        m = SLID.search(text)
        base = int(m.group(1), 16) if m else link
        want = elf_bytes(elf, func, READ_BYTES)
        want_addr = func + base - link
        out = self.debugger(cmd, ["azos-slide %#x" % base, *commands(name, want_addr)[1:], "detach"])
        why = "the debugger did not finish" if out is None else judge_read(out, want_addr, want)
        if why:
            return fail("after azos-slide %#x: %s" % (base, why))
        print("      %s at %#x after azos-slide %#x, %d bytes as in the ELF" % (FUNCTION, want_addr, base, READ_BYTES))

        # 3. the canary
        out = self.debugger(cmd, ["azos-slide %#x" % (base + SLIDE_STEP), *commands(name, want_addr)[1:], "detach"])
        if out is not None and judge_read(out, want_addr, want) is None:
            return fail("canary did not bite: the same read matched after azos-slide %#x" % (base + SLIDE_STEP))
        print("      canary: azos-slide %#x does not match" % (base + SLIDE_STEP))
        return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in debug_script.DEBUGGERS or "AZOS_OUT" not in os.environ:
        print("usage: AZOS_OUT=<dir> debug_row.py <riscv64|aarch64|x86_64>", file=sys.stderr)
        return 2
    logs = os.environ.get("CI_LOG_DIR") or tempfile.mkdtemp(prefix="debug-row.")
    os.makedirs(logs, exist_ok=True)
    return Row(argv[0], azos_tools.ROOT, os.environ["AZOS_OUT"], logs).run()


if __name__ == "__main__":
    sys.exit(main())
