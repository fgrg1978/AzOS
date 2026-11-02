#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""A configuration that asks for a symbol the Kconfig tree then refuses.

kconfiglib (and so `olddefconfig`) drops `CONFIG_X=y` silently when X's
dependencies are unmet: no warning, exit 0, and the written `.config` no longer
says it was asked. For an option like VIRT_SPLIT that is a lie (the image would
run another role). This reads a config before it is expanded and fails, naming
each symbol set to y that comes out n and the dependency that refused it.

    python3 tools/build/kconfig_dropped.py CONFIG [CONFIG...]   # exit 1 on a drop

`make defconfig-NAME` and `make olddefconfig` run it first; check_presets runs
it over every committed defconfig.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

Y = 2  # kconfiglib's value of a symbol set to y


def dropped(kconf):
    """[(name, dependency)] of the symbols the loaded config sets to y that are not y."""
    import kconfiglib

    return [(s.name, kconfiglib.expr_str(s.direct_dep))
            for s in kconf.unique_defined_syms
            if s.user_value == Y and s.tri_value != Y]


def main(argv):
    from kconfiglib import Kconfig

    if not argv:
        print(__doc__)
        return 2
    paths = [os.path.abspath(a) for a in argv]
    os.chdir(azos_tools.ROOT)
    kconf = Kconfig("Kconfig", warn_to_stderr=False)
    rc = 0
    for path in paths:
        kconf.load_config(path)
        for name, dep in dropped(kconf):
            print(f"kconfig: {path}: CONFIG_{name}=y is refused (depends on {dep}); "
                  "it would be dropped silently", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
