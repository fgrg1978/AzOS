#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""rr_qemu.py — QEMU record/replay for gate rows (host-side only; no kernel change).

Three uses of one file:

  qemu-system-<arch> (a symlink on PATH, put there by tools/dev/rr_row.sh)
      With RR_DIR set it is the RECORD wrapper: it takes the QEMU command line a
      gate row built, refuses what record/replay cannot reproduce, keeps the
      kernel and the disk images the run starts from, adds
      `-icount shift=0,sleep=off,rr=record,rrfile=...` and becomes QEMU (exec, so
      the pid the row kills is QEMU's). Without RR_DIR it just becomes QEMU.

  rr_qemu.py replay-cmd DIR [--boot K] [--gdb [--port N]]
      The replay command of boot K of a recording (shell-quoted, one line).
      --gdb adds `-gdb tcp::PORT -S`: the stub waits paused at the first
      instruction.

  rr_qemu.py check -- QEMU-ARGS...
      Prints why record/replay refuses that command line (exit 1), or nothing.

What record/replay cannot do (QEMU 11.0, TCG only) and this tool refuses:
  * HVF / KVM / WHPX: the instruction counter that orders every event exists only
    in TCG.
  * Network backends of the host (-netdev user|tap|..., -nic, -net, virtio-net on
    them): the packets come from outside the recording. -netdev needs
    filter-replay; the rows that use it are not supported.
  * Host sockets, ptys, pipes and files as a guest console (-chardev socket|pty|
    pipe|udp, -serial tcp:), the stall watcher's monitor and gdb stubs, -qmp:
    outside input the recording would not hold.
  * USB passthrough, audio, a window (-display cocoa|sdl|vnc), host directory
    shares (-virtfs, -fsdev), -object rng-random: the host decides what they
    return.
  * Disks other than `-drive if=none,file=...` (blkreplay wraps those) and
    read-only pflash; -blockdev, -hda, -cdrom, if=virtio.
  * -accel tcg,thread=multi: icount runs the vCPUs round-robin in one thread.
  Not refused, but a limit of the method: with -smp N the vCPUs interleave
  deterministically but NOT as in the gate's unrecorded run (multi-threaded TCG,
  real timing), so a failure that needs that interleaving may never show while
  recording; that is why rr_row.sh repeats runs.
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

ICOUNT = "shift=0,sleep=off"
FILE_OPTS = ("-kernel", "-initrd", "-dtb")  # -bios too, unless it names a built-in firmware
SOCKET_CHARDEVS = ("socket", "pty", "pipe", "udp", "tty", "serial", "parport", "spiceport", "braille", "msmouse")
PROGRAMS = ("riscv64", "aarch64", "x86_64")


def kv(opt):
    """'a=1,b,c=x' -> list of (key, value-or-None), keeping a leading bare word as key."""
    out = []
    for part in opt.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out.append((k, v))
        elif part:
            out.append((part, None))
    return out


def get(opt, key):
    for k, v in kv(opt):
        if k == key:
            return v
    return None


def isa_of(prog):
    m = re.search(r"qemu-system-([a-z0-9_]+)$", prog)
    return m.group(1) if m else None


def refusals(argv):
    """Why record/replay cannot take this command line (list of messages)."""
    why = []
    i = 0
    n = len(argv)

    def arg(j):
        return argv[j + 1] if j + 1 < n else ""

    while i < n:
        a = argv[i]
        if a in ("-enable-kvm", "-enable-hax"):
            why.append(f"{a}: record/replay is TCG only (no HVF/KVM)")
        elif a in ("-accel", "-machine", "-M"):
            v = arg(i)
            acc = get(v, "accel") if a != "-accel" else v.split(",")[0]
            if acc and acc.split(":")[0] != "tcg":
                why.append(f"{a} {v}: record/replay is TCG only (no HVF/KVM/WHPX)")
            if "thread=multi" in v:
                why.append(f"{a} {v}: icount runs the vCPUs in one thread; thread=multi cannot be recorded")
        elif a in ("-netdev", "-net", "-nic"):
            v = arg(i)
            if v.split(",")[0] != "none":
                why.append(f"{a} {v}: a network backend of the host is not part of the recording (virtio-net with a host backend cannot be replayed)")
        elif a == "-device":
            v = arg(i)
            dev = v.split(",")[0]
            if dev.startswith(("usb-host", "usb-redir", "usb-audio")) or dev in ("intel-hda", "ich9-intel-hda", "AC97", "es1370", "sb16"):
                why.append(f"-device {dev}: host passthrough or audio cannot be recorded")
            if dev.startswith(("virtio-9p", "virtio-net", "e1000", "rtl8139", "vmxnet3", "pcnet", "ne2k")) and get(v, "netdev") not in (None, "none"):
                why.append(f"-device {dev}: network device on a host backend")
        elif a == "-chardev":
            v = arg(i)
            back = v.split(",")[0]
            if back in SOCKET_CHARDEVS:
                why.append(f"-chardev {v}: a {back} chardev brings input from outside the recording")
        elif a in ("-serial", "-monitor", "-parallel"):
            v = arg(i)
            if re.match(r"(tcp|telnet|udp|unix|pty|pipe|tty|/dev/|socket)", v) or "server=on" in v:
                why.append(f"{a} {v}: a host socket or device cannot be recorded (the stall watcher's monitor? unset STALL_WATCH)")
        elif a in ("-qmp", "-qmp-pretty"):
            why.append(f"{a}: a control socket changes the run; use the replay for that")
        elif a in ("-gdb", "-s", "-S"):
            why.append(f"{a}: attach gdb to the REPLAY (rr_replay.sh --gdb), not to the recording (unset STALL_WATCH)")
        elif a in ("-display",) and arg(i) not in ("none",):
            why.append(f"-display {arg(i)}: host window input cannot be recorded")
        elif a in ("-vnc", "-spice", "-audiodev", "-soundhw", "-audio"):
            why.append(f"{a}: host display or audio cannot be recorded")
        elif a in ("-virtfs", "-fsdev"):
            why.append(f"{a}: a host directory share cannot be recorded")
        elif a == "-object" and re.match(r"rng-(random|egd)", arg(i)):
            why.append(f"-object {arg(i)}: host entropy is not part of the recording")
        elif a in ("-hda", "-hdb", "-hdc", "-hdd", "-cdrom", "-blockdev", "-mtdblock", "-sd", "-fda", "-fdb", "-pflash"):
            why.append(f"{a}: only `-drive if=none,file=...` disks are wrapped for replay")
        elif a == "-drive":
            v = arg(i)
            iface = get(v, "if")
            if iface == "pflash":
                if get(v, "readonly") not in ("on", "true", "yes"):
                    why.append(f"-drive {v}: writable pflash cannot be replayed (make it readonly=on)")
            elif iface != "none":
                why.append(f"-drive {v}: needs if=none (a -device then names the drive); blkreplay wraps only those")
            elif get(v, "file") is None:
                why.append(f"-drive {v}: no file=")
        elif a in ("-incoming", "-loadvm", "-replay"):
            why.append(f"{a}: not combinable with a recording")
        elif a == "-icount":
            if get(arg(i), "rr"):
                why.append(f"-icount {arg(i)}: the command line already records or replays")
        elif a == "-cpu" and arg(i).split(",")[0] == "host":
            why.append("-cpu host: record/replay is TCG only")
        i += 1
    return why


def snapshot_flag(argv):
    return "-snapshot" in argv


def final_args(spec, d, mode, gdb_port=None):
    """The QEMU arguments (without the program) of one boot of a recording.

    spec: {"argv": [...], "files": {"<argv index>": "<file in d>"}, "rr": "<rr file in d>"}.
    """
    argv = spec["argv"]
    files = spec["files"]
    out = []
    extra = []
    icount_done = False
    i = 0
    n = len(argv)
    while i < n:
        a = argv[i]
        if str(i + 1) in files and a in FILE_OPTS + ("-bios",):
            out += [a, os.path.join(d, files[str(i + 1)])]
            i += 2
            continue
        if a == "-snapshot":
            i += 1
            continue
        if a == "-drive" and i + 1 < n and get(argv[i + 1], "if") == "none":
            v = argv[i + 1]
            did = get(v, "id") or "drive0"
            parts = []
            for k, val in kv(v):
                if k == "file":
                    val = os.path.join(d, files[str(i + 1)])
                elif k == "id":
                    val = did + "-direct"
                elif k in ("snapshot", "readonly"):
                    continue
                parts.append(k if val is None else f"{k}={val}")
            if get(v, "id") is None:
                parts.append(f"id={did}-direct")
            parts.append("snapshot=on")
            out += ["-drive", ",".join(parts)]
            extra += ["-drive", f"driver=blkreplay,if=none,image={did}-direct,id={did}"]
            i += 2
            continue
        if a == "-icount" and i + 1 < n:
            out += ["-icount", f"{argv[i + 1]},rr={mode},rrfile={os.path.join(d, spec['rr'])}"]
            icount_done = True
            i += 2
            continue
        out.append(a)
        i += 1
    if not icount_done:
        out += ["-icount", f"{ICOUNT},rr={mode},rrfile={os.path.join(d, spec['rr'])}"]
    out += extra
    if gdb_port is not None:
        out += ["-gdb", f"tcp::{gdb_port}", "-S"]
    return out


def collect_files(argv):
    """index in argv of the VALUE of an option -> role, for the files the run starts from."""
    found = {}
    for i, a in enumerate(argv[:-1]):
        v = argv[i + 1]
        if a in FILE_OPTS and os.path.isfile(v):
            found[i + 1] = "file"
        elif a == "-bios" and os.path.isfile(v):
            found[i + 1] = "file"
        elif a == "-drive" and get(v, "if") == "none":
            f = get(v, "file")
            if f and os.path.isfile(f):
                found[i + 1] = "disk"
    return found


def clone(src, dst):
    if subprocess.call(["cp", "-c", src, dst], stderr=subprocess.DEVNULL) != 0:
        shutil.copyfile(src, dst)


def find_elf(image, search_dirs):
    """The ELF behind an aarch64 flat Image: the sibling `X` of an `X.img` byte-equal to it."""
    try:
        want = os.path.getsize(image)
    except OSError:
        return None
    cands = []
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for root, _dirs, names in os.walk(d):
            for nm in names:
                if nm.endswith(".img") and os.path.isfile(os.path.join(root, nm[:-4])):
                    cands.append(os.path.join(root, nm))
            if root.count(os.sep) - d.count(os.sep) > 6:
                _dirs[:] = []
    for c in cands:
        try:
            if os.path.getsize(c) == want and open(c, "rb").read() == open(image, "rb").read():
                return c[:-4]
        except OSError:
            pass
    return None


def stdout_path():
    try:
        import fcntl
        raw = fcntl.fcntl(1, 50, b"\0" * 1024)  # F_GETPATH (macOS)
    except (OSError, ImportError):
        return None
    return raw.split(b"\0", 1)[0].decode(errors="replace") or None


def real_qemu(name):
    here = os.path.dirname(os.path.abspath(sys.argv[0]))
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.path.abspath(d) != here:
            cand = os.path.join(d, name)
            # Any other stand-in (the gate's qemu_tap.py, put first on PATH by ci_check.sh)
            # is a script behind a symlink; QEMU is a binary.
            if os.path.isfile(cand) and os.access(cand, os.X_OK) and not os.path.realpath(cand).endswith(".py"):
                return cand
    sys.exit(f"rr_qemu: no {name} on PATH outside {here}")


def fork_console_keeper(path_dst):
    """Keep what QEMU prints, even after the row deletes its log.

    stdout is a file the row made; a descendant holds it open for reading (so the
    bytes outlive the row's `rm`), waits for
    QEMU (this pid, after exec) to end and copies the file's bytes to path_dst.
    """
    src = stdout_path()
    try:
        keep = os.open(src, os.O_RDONLY) if src else -1
    except OSError:
        keep = -1
    if keep < 0:
        return
    parent = os.getpid()
    if os.fork() != 0:
        os.close(keep)
        return
    os.setsid()
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    import time
    while True:
        try:
            os.kill(parent, 0)
        except OSError:
            break
        time.sleep(0.05)
    time.sleep(0.2)
    try:
        buf = b""
        off = 0
        while True:
            chunk = os.pread(keep, 1 << 20, off)
            if not chunk:
                break
            buf += chunk
            off += len(chunk)
        with open(path_dst, "wb") as f:
            f.write(buf)
    finally:
        os._exit(0)


def record_main():
    name = os.path.basename(sys.argv[0])
    args = sys.argv[1:]
    rr_dir = os.environ.get("RR_DIR")
    real = real_qemu(name)
    if not rr_dir:
        os.execv(real, [real] + args)
    why = refusals(args)
    if why:
        with open(os.path.join(rr_dir, "refused.txt"), "a", encoding="utf-8") as f:
            f.write("".join(f"{name}: {w}\n" for w in why))
        sys.stderr.write("".join(f"rr_qemu: refused: {w}\n" for w in why))
        sys.exit(97)
    k = 1
    while True:
        bd = os.path.join(rr_dir, f"boot-{k}")
        try:
            os.mkdir(bd)
            break
        except FileExistsError:
            k += 1
    files = {}
    n_disk = 0
    for idx, role in sorted(collect_files(args).items()):
        src = args[idx] if args[idx - 1] != "-drive" else get(args[idx], "file")
        if role == "disk":
            dst = f"disk-{n_disk}.img"
            n_disk += 1
        else:
            dst = os.path.basename(args[idx - 1]).lstrip("-")
        clone(src, os.path.join(bd, dst))
        files[str(idx)] = dst
    spec = {"isa": isa_of(name), "prog": name, "argv": args, "files": files, "rr": "rr.bin"}
    kern = next((v for key, v in files.items() if args[int(key) - 1] == "-kernel"), None)
    if kern and spec["isa"] == "aarch64":
        dirs = [os.path.join(os.environ.get("AZOS_OUT", ""), "target"), os.path.join(os.environ.get("CI_LOG_DIR", os.path.join(os.environ.get("AZOS_OUT", ""), "build/ci-logs")))]
        elf = find_elf(os.path.join(bd, kern), dirs)
        if elf:
            clone(elf, os.path.join(bd, "kernel.elf"))
            spec["elf"] = "kernel.elf"
    elif kern:
        spec["elf"] = kern
    with open(os.path.join(bd, "spec.json"), "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=1)
    fork_console_keeper(os.path.join(bd, "console.log"))
    qargs = final_args(spec, bd, "record")
    os.execv(real, [real] + qargs)


def replay_cmd(d, boot, gdb, port):
    with open(os.path.join(d, f"boot-{boot}", "spec.json"), encoding="utf-8") as f:
        spec = json.load(f)
    bd = os.path.join(d, f"boot-{boot}")
    qargs = final_args(spec, bd, "replay", port if gdb else None)
    return [spec["prog"]] + qargs, spec


MARKER = re.compile(r"^(not ok \d+ - |Bail out!)|KERNEL PANIC|\bpanicked\b")


def norm(text):
    return text.replace("\r", "")


def console_of(d, boot):
    try:
        with open(os.path.join(d, f"boot-{boot}", "console.log"), "rb") as f:
            return norm(f.read().decode("utf-8", "replace"))
    except OSError:
        return None


def boots_of(d):
    return sorted(int(m.group(1)) for m in (re.fullmatch(r"boot-(\d+)", n) for n in os.listdir(d)) if m)


def find_marker(text, until=None):
    """First console line that is a failure (not ok / Bail out / panic) or matches `until`."""
    pat = re.compile(until) if until else None
    for line in text.splitlines():
        if (pat and pat.search(line)) or (not pat and MARKER.search(line)):
            return line
    return None


TAP = re.compile(r"^(1\.\.\d+|(not )?ok \d+ - .*|# ktest: .*|Bail out!.*)$")


def tap_lines(text):
    return [l for l in norm(text).splitlines() if TAP.match(l)]


def compare(recorded, replayed, marker):
    """(ok, message): the replay printed what the recording did, marker line included.

    ok needs the whole console identical; the message also says whether the TAP lines are.
    """
    a, b = norm(recorded), norm(replayed)
    ta, tb = tap_lines(a), tap_lines(b)
    tap = f"{len(ta)} TAP lines identical" if ta == tb else "TAP lines DIFFER"
    if a == b:
        if marker and marker not in b.splitlines():
            return False, f"identical console, yet the marker line is absent: {marker}"
        return True, f"console identical ({tap})" + (f", marker reproduced: {marker}" if marker else "")
    la, lb = a.splitlines(), b.splitlines()
    for k in range(min(len(la), len(lb))):
        if la[k] != lb[k]:
            return False, f"consoles diverge at line {k + 1}: recorded {la[k]!r}, replayed {lb[k]!r} ({tap})"
    return False, f"one console ends early: recorded {len(la)} lines, replayed {len(lb)} ({tap})"


def main(argv):
    if len(argv) >= 2 and argv[1] == "marker":
        d, until = argv[2], (argv[argv.index("--until") + 1] if "--until" in argv else None)
        for k in boots_of(d):
            text = console_of(d, k)
            m = find_marker(text, until) if text else None
            if m:
                print(f"{k}\t{m}")
                return 0
        return 1
    if len(argv) >= 2 and argv[1] == "compare":
        d, boot, rlog = argv[2], int(argv[3]), argv[4]
        marker = None
        try:
            with open(os.path.join(d, "meta.json"), encoding="utf-8") as f:
                marker = json.load(f).get("marker")
        except (OSError, ValueError):
            pass
        rec = console_of(d, boot)
        if rec is None:
            print("no recorded console.log in the recording")
            return 2
        with open(rlog, "rb") as f:
            ok, msg = compare(rec, f.read().decode("utf-8", "replace"), marker)
        print(msg)
        return 0 if ok else 1
    if len(argv) >= 2 and argv[1] == "replay-cmd":
        d, boot, gdb, port = None, 1, False, 1234
        rest = argv[2:]
        while rest:
            a = rest.pop(0)
            if a == "--boot":
                boot = int(rest.pop(0))
            elif a == "--gdb":
                gdb = True
            elif a == "--port":
                port = int(rest.pop(0))
            else:
                d = a
        if not d:
            sys.exit("usage: rr_qemu.py replay-cmd DIR [--boot K] [--gdb [--port N]]")
        cmd, _spec = replay_cmd(d, boot, gdb, port)
        print(" ".join(shlex.quote(c) for c in cmd))
        return 0
    if len(argv) >= 2 and argv[1] == "check":
        why = refusals(argv[argv.index("--") + 1:] if "--" in argv else argv[2:])
        for w in why:
            print(w)
        return 1 if why else 0
    sys.exit(__doc__)


if __name__ == "__main__":
    if isa_of(os.path.basename(sys.argv[0])):
        record_main()
    sys.exit(main(sys.argv))
