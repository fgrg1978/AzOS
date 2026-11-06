# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host tests of tools/sign/check_board_keys.py.  Run: python3 tests/host/gate-tools-tests/test_check_board_keys.py"""
import ast
import os
import sys
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.."))
sys.path.insert(0, os.path.join(ROOT, "tools/sign"))
import check_board_keys  # noqa: E402

SRC = os.path.join(ROOT, "tools/sign/check_board_keys.py")


class HelperPaths(unittest.TestCase):
    def test_helpers_exist(self):
        make_mbl, topology_tests = check_board_keys.helper_paths()
        self.assertTrue(os.path.isfile(make_mbl), make_mbl)
        self.assertTrue(os.path.isfile(os.path.join(topology_tests, "Cargo.toml")), topology_tests)

    def test_no_unbound_names(self):
        """Every name a function reads is a parameter, local, global or builtin (the `here` rot)."""
        tree = ast.parse(open(SRC, encoding="utf-8").read())
        known = set(dir(__builtins__)) | {"__doc__", "__file__", "__name__"}
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                known.add(n.name)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                known |= {(a.asname or a.name).split(".")[0] for a in n.names}
            else:
                known |= {t.id for t in ast.walk(n) if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store)}
        missing = []
        for f in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            local = {a.arg for a in ast.walk(f.args) if isinstance(a, ast.arg)}
            for t in ast.walk(f):
                if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store):
                    local.add(t.id)
                elif isinstance(t, (ast.Import, ast.ImportFrom)):
                    local |= {(a.asname or a.name).split(".")[0] for a in t.names}
                elif isinstance(t, ast.FunctionDef):
                    local.add(t.name)
                elif isinstance(t, ast.ExceptHandler) and t.name:
                    local.add(t.name)
            for t in ast.walk(f):
                if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Load) and t.id not in local | known:
                    missing.append(f"{f.name}: {t.id}")
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
