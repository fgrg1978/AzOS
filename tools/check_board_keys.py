#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""check_board_keys.py — a board image never carries the TEST key (wave 11 BOARDIMG).

The Makefile builds two ML services: `build/mlsrv.elf` for the QEMU disks
(`--features dev-key`, embeds `tools/keys/test_pub.bin`) and
`build/board/mlsrv.elf` for the board volume (the key TOPOLOGY_PUBKEY_PATH
names). These checks say what each board artifact contains, from the bytes:

    check_board_keys.py key  <keyfile> <test_pub>
        <keyfile> is a 32-byte key and is not the test key.
    check_board_keys.py elf  <keyfile> <test_pub> <mlsrv.elf>
        the ELF embeds <keyfile>'s 32 bytes and not the test key's.
    check_board_keys.py pair <priv> <pub> <test_priv> <test_pub>
        <priv> is a 32-byte seed whose public half is <pub>, and neither it nor
        <pub> is the test pair (a missing test file skips only that comparison).
    check_board_keys.py sigs <image> <pub>
        CONFIG.SIG and the ML data signatures on the image verify under <pub>,
        checked by the kernel's own verifier code (tests/host/topology-tests'
        `verify_board_volume`, built with TOPOLOGY_PUBKEY_PATH=<pub>).
    check_board_keys.py disk <image> <board_table.rs> <qemu_mlsrv.elf> <test_pub>
        the image's MLSRV.ELF (read back with mcopy) hashes to the board
        table's MLSRV.ELF row, embeds no test key, and is not the QEMU
        service. A missing <qemu_mlsrv.elf> or <test_pub> skips only the
        comparison that needs it (a fresh tree has neither).

Exit 0 when it holds, 1 (one line on stderr) when it does not.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

KEY_LEN = 32


def read_optional(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def check_key(key, test_pub):
    """Return a problem string, or None. `key`/`test_pub` are bytes (test_pub may be None)."""
    if len(key) != KEY_LEN:
        return f"the key is {len(key)} bytes, not a {KEY_LEN}-byte Ed25519 public key"
    if test_pub is not None and key == test_pub:
        return "the key is the TEST key (tools/keys/test_pub.bin)"
    return None


def derive_public(seed):
    """The Ed25519 public half of a 32-byte seed (needs `cryptography`)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def check_pair(priv, pub, test_priv, test_pub):
    """Return a problem string, or None."""
    if len(priv) != KEY_LEN:
        return f"the private key is {len(priv)} bytes, not a {KEY_LEN}-byte seed"
    if test_priv is not None and priv == test_priv:
        return "the signing key is the TEST key (tools/keys/test_priv.bin)"
    problem = check_key(pub, test_pub)
    if problem:
        return problem
    if derive_public(priv) != pub:
        return "TOPOLOGY_PRIVKEY_PATH is not the private half of TOPOLOGY_PUBKEY_PATH"
    return None


def check_sigs(image, pub_path):
    """Run the kernel's verifier code over the image's signed files."""
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    import device_provision
    rec = device_provision.read_record(image)
    if rec is None:
        return f"{image} carries no device record"
    with tempfile.TemporaryDirectory() as d:
        names = ["CONFIG.INI", "CONFIG.SIG", "MLP.RML", "MLP.SIG", "POLICY.GGF", "POLICY.SIG"]
        paths = {}
        for n in names:
            paths[n] = os.path.join(d, n)
            with open(paths[n], "wb") as f:
                f.write(read_from_image(image, n))
        env = dict(os.environ, TOPOLOGY_PUBKEY_PATH=os.path.abspath(pub_path))
        r = subprocess.run(
            ["cargo", "run", "-q", "--release", "--bin", "verify_board_volume", "--",
             paths["CONFIG.INI"], paths["CONFIG.SIG"], rec[0].hex(),
             paths["MLP.RML"], paths["MLP.SIG"], paths["POLICY.GGF"], paths["POLICY.SIG"]],
            cwd=os.path.join(here, "..", "tests", "host", "topology-tests"), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = r.stdout.decode(errors="replace")
        print(out, end="")
        if r.returncode != 0:
            return "a signature on the board volume does not verify under the board key"
    return None


def check_elf(elf, key, test_pub):
    """The ELF carries the named key and not the test key."""
    if test_pub is not None and len(test_pub) == KEY_LEN and test_pub in elf:
        return "the ML service embeds the TEST key (tools/keys/test_pub.bin)"
    if key not in elf:
        return "the ML service does not embed the key TOPOLOGY_PUBKEY_PATH names"
    return None


def table_digest(table_text, name):
    m = re.search(r'\("%s", \[([^\]]*)\]\)' % re.escape(name), table_text)
    if not m:
        return None
    return bytes(int(b, 16) for b in m.group(1).split(","))


def check_disk(mlsrv, table_text, qemu_elf, test_pub):
    """`mlsrv` is the MLSRV.ELF read back from the board image."""
    digest = hashlib.sha256(mlsrv).digest()
    listed = table_digest(table_text, "MLSRV.ELF")
    if listed is None:
        return "the board image-hash table has no MLSRV.ELF row"
    if listed != digest:
        return (f"the image's MLSRV.ELF is sha256 {digest.hex()[:16]}..., the board table "
                f"lists {listed.hex()[:16]}...")
    if test_pub is not None and len(test_pub) == KEY_LEN and test_pub in mlsrv:
        return "the image's MLSRV.ELF embeds the TEST key"
    if qemu_elf is not None and hashlib.sha256(qemu_elf).digest() == digest:
        return "the image's MLSRV.ELF is the QEMU (dev-key) build"
    return None


def read_from_image(image, name):
    r = subprocess.run(["mcopy", "-n", "-i", image, f"::{name}", "-"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        sys.exit(f"check_board_keys.py: cannot read ::{name} from {image}: "
                 f"{r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    mode = argv[1]
    problem = None
    if mode == "key" and len(argv) == 4:
        problem = check_key(read_optional(argv[2]) or b"", read_optional(argv[3]))
    elif mode == "elf" and len(argv) == 5:
        key = read_optional(argv[2]) or b""
        elf = read_optional(argv[4])
        if elf is None:
            sys.exit(f"check_board_keys.py: cannot read {argv[4]}")
        problem = check_key(key, read_optional(argv[3])) or \
            check_elf(elf, key, read_optional(argv[3]))
    elif mode == "pair" and len(argv) == 6:
        problem = check_pair(read_optional(argv[2]) or b"", read_optional(argv[3]) or b"",
                             read_optional(argv[4]), read_optional(argv[5]))
    elif mode == "sigs" and len(argv) == 4:
        problem = check_sigs(argv[2], argv[3])
    elif mode == "disk" and len(argv) == 6:
        table = read_optional(argv[3])
        if table is None:
            sys.exit(f"check_board_keys.py: cannot read {argv[3]}")
        problem = check_disk(read_from_image(argv[2], "MLSRV.ELF"),
                             table.decode("utf-8"), read_optional(argv[4]),
                             read_optional(argv[5]))
    else:
        sys.exit(__doc__)
    if problem:
        print(f"check_board_keys.py: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
