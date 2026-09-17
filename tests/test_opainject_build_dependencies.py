import unittest

from port_review_test_support import ROOT


class OpainjectBuildDependencyTests(unittest.TestCase):
    def test_opainject_uses_available_sdk_instead_of_pinning_removed_165_sdk(self):
        makefile = (ROOT / "BaseBin/opainject/Makefile").read_text()

        self.assertIn("TARGET := iphone:clang:latest:11.0", makefile)
        self.assertNotIn("iphone:clang:16.5", makefile)

    def test_opainject_does_not_link_unused_coresymbolication(self):
        makefile = (ROOT / "BaseBin/opainject/Makefile").read_text()
        rop_source = (ROOT / "BaseBin/opainject/rop_inject.m").read_text()

        self.assertNotIn("opainject_PRIVATE_FRAMEWORKS = CoreSymbolication", makefile)
        self.assertNotIn('#import "CoreSymbolication.h"', rop_source)


if __name__ == "__main__":
    unittest.main()
