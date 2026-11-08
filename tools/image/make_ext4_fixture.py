#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Build the ext4 volume the ring-3 ext4 rows read (Kconfig FS_EXT4_RING3).

Usage: make_ext4_fixture.py OUT.img [MIB]

A small tree, laid out under a scratch directory next to OUT and written by
the host's `mke2fs -d` with the feature set `mke2fs -t ext4` makes today,
named in full (`-O none,...`) so the host's mke2fs.conf changes nothing; the
UUID, the hash seed and the clock are fixed, so the image is the same bytes on
every build. Then `e2fsck -fD` indexes its large directory (htree).

  hello.txt          "hello from ext4\\n"
  lines.txt          1000 lines "ext4 line NNNN\\n": `wc` answers 1000 3000 15000
  deep/a/needle.txt  "the needle is here\\n", for `rg needle`
  many/              300 files, a directory of several blocks
  link               symlink to hello.txt

e2fsprogs is found on PATH (a directory with both mke2fs and e2fsck), else as
Homebrew's keg (`brew --prefix e2fsprogs`), which is not linked onto PATH.
"""
import os
import shutil
import subprocess
import sys

FEATURES = ("has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,"
            "sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum")
UUID = "01234567-89ab-cdef-0123-456789abcdef"


def e2fsprogs():
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.isfile(os.path.join(d, "mke2fs")) and os.path.isfile(os.path.join(d, "e2fsck")):
            return d
    try:
        prefix = subprocess.run(["brew", "--prefix", "e2fsprogs"], capture_output=True, text=True).stdout.strip()
    except OSError:
        prefix = ""
    d = os.path.join(prefix, "sbin")
    if prefix and os.path.isfile(os.path.join(d, "mke2fs")) and os.path.isfile(os.path.join(d, "e2fsck")):
        return d
    sys.exit("make_ext4_fixture.py: e2fsprogs (mke2fs, e2fsck) is neither on PATH nor a Homebrew keg")


def tree(root):
    if os.path.isdir(root):
        shutil.rmtree(root)
    os.makedirs(os.path.join(root, "deep", "a"))
    os.makedirs(os.path.join(root, "many"))
    with open(os.path.join(root, "hello.txt"), "w") as f:
        f.write("hello from ext4\n")
    with open(os.path.join(root, "lines.txt"), "w") as f:
        for i in range(1000):
            f.write("ext4 line %04d\n" % i)
    with open(os.path.join(root, "deep", "a", "needle.txt"), "w") as f:
        f.write("the needle is here\n")
    for i in range(300):
        with open(os.path.join(root, "many", "an-entry-with-a-rather-long-name-%04d" % i), "w") as f:
            f.write("%d\n" % i)
    os.symlink("hello.txt", os.path.join(root, "link"))


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: make_ext4_fixture.py OUT.img [MIB]")
    out = sys.argv[1]
    mib = int(sys.argv[2]) if len(sys.argv) == 3 else 8
    root = out + ".tree"
    tree(root)
    tools = e2fsprogs()
    env = dict(os.environ, E2FSPROGS_FAKE_TIME="1700000000", MKE2FS_CONFIG="/dev/null", E2FSCK_CONFIG="/dev/null")
    if os.path.exists(out):
        os.unlink(out)
    subprocess.run([os.path.join(tools, "mke2fs"), "-q", "-F", "-T", "default", "-b", "4096", "-I", "256",
                    "-O", "none," + FEATURES, "-U", UUID, "-E", "hash_seed=" + UUID, "-d", root, out, "%dM" % mib],
                   env=env, check=True, stdout=subprocess.DEVNULL)
    r = subprocess.run([os.path.join(tools, "e2fsck"), "-f", "-y", "-D", out], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode not in (0, 1):
        sys.exit("make_ext4_fixture.py: e2fsck -fD %s answered %d" % (out, r.returncode))
    shutil.rmtree(root)
    print("[DISK] ext4 volume: %s (%d MiB)" % (out, mib))


if __name__ == "__main__":
    main()
