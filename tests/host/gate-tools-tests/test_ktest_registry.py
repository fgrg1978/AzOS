# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host tests of tools/gate/ktest_registry.py.  Run: python3 tests/host/gate-tools-tests/test_ktest_registry.py"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.."))
sys.path.insert(0, os.path.join(ROOT, "tools/gate"))
import ktest_registry as kr  # noqa: E402

MAIN = '''
mod always;
#[cfg(feature = "ktest")]
mod gated;
#[cfg(target_arch = "aarch64")]
#[path = "arm_only.rs"]
mod arm;
mod inline {
    #[cfg(not(feature = "off"))]
    mod deep;
}
'''
ALWAYS = '''
azos_ktest::ktest! { fn a_one() { Ok(()) } }
azos_ktest::ktest_late! {
    #[cfg(feature = "late")]
    fn a_late() { let s = "ktest! { fn in_a_string() }"; Ok(()) }
}
// ktest! { fn in_a_comment() {} }
'''


def tree(files):
    d = tempfile.mkdtemp()
    for name, text in files.items():
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
    return d


class Registry(unittest.TestCase):
    def names(self, files, isa, feats):
        return sorted(r[0] for r in kr.registry(isa, feats, ksrc=tree(files)))

    def files(self):
        return {"main.rs": MAIN, "always.rs": ALWAYS, "gated.rs": "ktest! { fn g_one() {} }",
                "arm_only.rs": "ktest! { fn arm_one() {} }", "inline/deep.rs": "ktest! { fn deep_one() {} }"}

    def test_cfg_of_the_site_the_module_and_the_isa(self):
        f = self.files()
        self.assertEqual(self.names(f, "rv", []), ["a_one", "deep_one"])
        self.assertEqual(self.names(f, "rv", ["ktest", "late"]), ["a_late", "a_one", "deep_one", "g_one"])
        self.assertEqual(self.names(f, "arm", []), ["a_one", "arm_one", "deep_one"])

    def test_a_feature_that_names_another_brings_it(self):
        table = kr.kconfig_to_cargo.cargo_features(os.path.join(ROOT, "kernel/Cargo.toml"))
        outer, inner = next((f, x) for f, xs in table.items() for x in xs if x in table)
        self.assertIn(inner, kr.feature_closure([outer]))

    def test_an_unreachable_site_a_duplicate_and_an_unknown_cfg_are_errors(self):
        f = self.files()
        f["stray.rs"] = "ktest! { fn stray() {} }"
        with self.assertRaises(kr.Unsupported):
            kr.registry("rv", [], ksrc=tree(f))
        f = self.files()
        f["gated.rs"] = "ktest! { fn a_one() {} }"
        with self.assertRaises(kr.Unsupported):
            kr.registry("rv", ["ktest"], ksrc=tree(f))
        f = self.files()
        f["always.rs"] = '#[cfg(mystery)]\nktest! { fn m() {} }'
        with self.assertRaises(kr.Unsupported):
            kr.registry("rv", [], ksrc=tree(f))

    def test_the_log_must_name_exactly_the_registered_tests(self):
        log = "1..2\nok 1 - a_one\nnot ok 2 - extra # why\n"
        self.assertEqual(kr.diff_against_log(["a_one", "b_two"], log), "not run: b_two; run but not in the source: extra")
        self.assertEqual(kr.diff_against_log(["a_one", "extra"], log), "")

    def test_the_real_tree_walks_on_every_isa(self):
        for isa in ("rv", "arm", "x86"):
            self.assertGreater(len(kr.registry(isa, ["ktest"])), 100, isa)


if __name__ == "__main__":
    unittest.main()
