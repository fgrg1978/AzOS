#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Type text into a running QEMU through its human monitor (`sendkey`).

    qemu_sendkeys.py [--delay S] [--wait S] [--raw | --command] SOCK TEXT...

SOCK is the unix socket of a monitor chardev (`-chardev socket,id=mon0,
path=SOCK,server=on,wait=off -mon chardev=mon0,mode=readline`). Each TEXT
argument is typed, then Enter. With `--raw` each argument is one QEMU key
name sent as it is, with no Enter (`f5`, `backspace`, `ctrl-alt-delete`): a
key press for a task that reads the events and not the typed line. With
`--command` each argument is one monitor command line, sent as it is
(`device_del stick`: a USB stick pulled out). Used by the gate's virtio-input rows: the
guest's serial stdin is silent, so every byte the shell reads came from the
virtio keyboard. Exit 0 once every key was sent, 1 if the monitor never
answered. `--keys` prints the QEMU key names for the text and sends nothing.
"""
import socket
import sys
import time

SPECIAL = {" ": "spc", "-": "minus", "=": "equal", ".": "dot", ",": "comma", "/": "slash",
           ";": "semicolon", "'": "apostrophe", "\\": "backslash", "[": "bracket_left",
           "]": "bracket_right", "`": "grave_accent", "\t": "tab", "\n": "ret"}
SHIFTED = {"_": "minus", "+": "equal", ":": "semicolon", '"': "apostrophe", "<": "comma",
           ">": "dot", "?": "slash", "|": "backslash", "{": "bracket_left",
           "}": "bracket_right", "~": "grave_accent", "!": "1", "@": "2", "#": "3", "$": "4",
           "%": "5", "^": "6", "&": "7", "*": "8", "(": "9", ")": "0"}


def key_names(text):
    out = []
    for ch in text:
        if ch in SPECIAL:
            out.append(SPECIAL[ch])
        elif ch in SHIFTED:
            out.append("shift-" + SHIFTED[ch])
        elif ch.isascii() and ch.isalpha():
            out.append(("shift-" + ch.lower()) if ch.isupper() else ch)
        elif ch.isascii() and ch.isdigit():
            out.append(ch)
        else:
            raise SystemExit("no key for %r" % ch)
    return out


def main(argv):
    args = argv[1:]
    delay, wait, only_names, raw, command = 0.15, 10.0, False, False, False
    while args and args[0].startswith("--"):
        opt = args.pop(0)
        if opt == "--delay":
            delay = float(args.pop(0))
        elif opt == "--wait":
            wait = float(args.pop(0))
        elif opt == "--keys":
            only_names = True
        elif opt == "--raw":
            raw = True
        elif opt == "--command":
            command = True
        else:
            raise SystemExit("unknown option " + opt)
    if only_names:
        for t in args:
            print(" ".join(key_names(t + "\n")))
        return 0
    if len(args) < 2:
        raise SystemExit(__doc__)
    path, texts = args[0], args[1:]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.time() + wait
    while True:
        try:
            s.connect(path)
            break
        except OSError:
            if time.time() > deadline:
                print("monitor socket never came up: " + path, file=sys.stderr)
                return 1
            time.sleep(0.2)
    s.settimeout(0.05)

    def drain():
        try:
            while s.recv(4096):
                pass
        except OSError:
            pass

    drain()
    for t in texts:
        if command:
            s.sendall((t + "\n").encode())
            time.sleep(delay)
            drain()
            continue
        for k in [t] if raw else key_names(t + "\n"):
            s.sendall(("sendkey %s\n" % k).encode())
            time.sleep(delay)
            drain()
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
