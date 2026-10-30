#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""debug_script.py — the debugger script of `make debug`.

    debug_script.py <riscv64|aarch64|x86_64> <kernel ELF> [--port N] [--out-dir DIR]

Writes DIR/debug_<isa>.gdb or DIR/debug_<isa>.py (an lldb module), picks the
debugger that serves the ISA from what is installed, and prints the command
that starts it. The script loads the ELF's symbols, connects to QEMU's gdbstub
on 127.0.0.1:PORT, and defines `azos-slide`.

KASLR: the kernel runs at a random base, so the ELF's addresses do not match
the running image until the debugger is told the base. The console prints it:
`[KASLR] image slid to 0x<base>, ...`. `azos-slide 0x<base>` reloads the
symbols at it. A kernel that was not slid runs at the ELF's addresses and
needs nothing.

Debugger per ISA: a gdb built for the ISA when one is installed, lldb for the
ISAs whose gdb is not (lldb reads ELF and speaks the gdb remote protocol).
Nothing is downloaded: with none of the candidates installed the tool says
which names it looked for.
"""
import argparse
import os
import shlex
import shutil
import sys

# In preference order. A name ending in `lldb` is driven with the module,
# every other with a gdb script.
DEBUGGERS = {
    "riscv64": ["riscv64-elf-gdb", "riscv64-unknown-elf-gdb", "riscv64-linux-gnu-gdb", "gdb-multiarch"],
    "aarch64": ["aarch64-elf-gdb", "aarch64-none-elf-gdb", "aarch64-linux-gnu-gdb", "gdb-multiarch", "lldb"],
    "x86_64": ["x86_64-elf-gdb", "x86_64-linux-gnu-gdb", "gdb-multiarch", "lldb"],
}

GDB_SCRIPT = """\
set pagination off
set confirm off
file {elf}
define azos-slide
  symbol-file {elf}
  set $azos_slide = (unsigned long)$arg0 - (unsigned long)&_text_start
  symbol-file {elf} -o $azos_slide
end
document azos-slide
Reload the kernel's symbols at the image base the console printed:
  [KASLR] image slid to 0x<base>   ->   azos-slide 0x<base>
end
target remote 127.0.0.1:{port}
"""

LLDB_MODULE = '''\
import lldb

ELF = {elf!r}
ADDR = "127.0.0.1:{port}"


def azos_slide(debugger, command, result, internal_dict):
    """azos-slide 0x<base>: reload the kernel's symbols at the image base the console printed."""
    target = debugger.GetSelectedTarget()
    found = target.FindSymbols("_text_start")
    if not command.strip() or found.GetSize() == 0:
        result.SetError("usage: azos-slide 0x<base>   (the base of `[KASLR] image slid to 0x<base>`)")
        return
    link = found.GetContextAtIndex(0).GetSymbol().GetStartAddress().GetFileAddress()
    slide = (int(command.strip(), 0) - link) & 0xFFFFFFFFFFFFFFFF
    if slide >= 1 << 63:
        slide -= 1 << 64
    error = target.SetModuleLoadAddress(target.GetModuleAtIndex(0), slide)
    if error.Fail():
        result.SetError(error.GetCString())


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("target create " + ELF)
    debugger.HandleCommand("command script add -f " + __name__ + ".azos_slide azos-slide")
    debugger.HandleCommand("gdb-remote " + ADDR)
'''


def pick_debugger(isa, path=None):
    """The first installed candidate of the ISA, as a full path, or None."""
    for name in DEBUGGERS[isa]:
        found = shutil.which(name, path=path)
        if found:
            return found
    return None


def write_script(isa, elf, port, out_dir, debugger):
    """Write the script for `debugger`; return the command line that starts it."""
    os.makedirs(out_dir, exist_ok=True)
    elf = os.path.abspath(elf)
    if os.path.basename(debugger) == "lldb":
        script = os.path.join(out_dir, "debug_%s.py" % isa)
        with open(script, "w") as f:
            f.write(LLDB_MODULE.format(elf=elf, port=port))
        return [debugger, "-o", "command script import " + script], script
    script = os.path.join(out_dir, "debug_%s.gdb" % isa)
    with open(script, "w") as f:
        f.write(GDB_SCRIPT.format(elf=elf, port=port))
    return [debugger, "-q", "-x", script], script


def batch_command(cmd, commands):
    """`cmd` (from write_script) run without a prompt: the script, then `commands`, then exit."""
    if os.path.basename(cmd[0]) == "lldb":
        return cmd + ["-b"] + [x for c in commands for x in ("-o", c)]
    return cmd + ["-batch"] + [x for c in commands for x in ("-ex", c)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1].strip())
    ap.add_argument("isa", choices=sorted(DEBUGGERS))
    ap.add_argument("elf")
    ap.add_argument("--port", type=int, default=1234)
    ap.add_argument("--out-dir", default=".")
    a = ap.parse_args(argv)
    if not os.path.isfile(a.elf):
        print("debug_script: no kernel ELF at %s (make build first)" % a.elf, file=sys.stderr)
        return 1
    debugger = pick_debugger(a.isa)
    if debugger is None:
        print("debug_script: no debugger for %s on this host, looked for: %s"
              % (a.isa, " ".join(DEBUGGERS[a.isa])), file=sys.stderr)
        return 1
    cmd, script = write_script(a.isa, a.elf, a.port, a.out_dir, debugger)
    print(" ".join(shlex.quote(c) for c in cmd))
    return 0


if __name__ == "__main__":
    sys.exit(main())
