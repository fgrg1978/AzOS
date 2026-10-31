# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# QEMU processes on this host. `pgrep -x` cannot do it: Linux truncates process
# names to 15 characters, so a qemu-system-* name never matches there.
qemu_count() { # qemu_count [pgid]: host-wide, or within one process group
    ps -axo pgid=,comm= | awk -v g="${1:-}" '/qemu-system/ && (g == "" || $1 == g) { n++ } END { print n + 0 }'
}
