# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Whether a snapshotted volume still carries the images a kernel was just built
# to bind. The images in one directory are rebuilt for whichever configuration
# built last, and a kernel's digest table is taken from them at its build, so a
# volume made before that rebuild holds other bytes and the kernel refuses every
# one of them.
volume_stale() { # volume_stale <volume> <image dir>: 0 when the volume is missing or older than an ELF
    [ -f "$1" ] || return 0
    [ -n "$(find "$2" -maxdepth 1 -name '*.elf' -newer "$1" -print -quit)" ]
}
