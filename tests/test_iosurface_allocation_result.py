import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class IOSurfaceAllocationResultTests(unittest.TestCase):
    def test_size_boundary_through_both_wrappers_and_provider(self):
        primitive_header = (ROOT / "BaseBin/libjailbreak/src/primitives.h").read_text()
        options = re.search(r"typedef enum\s*\{[^}]*\} kalloc_options;", primitive_header).group(0)
        implementation = options + "\n"
        path = "BaseBin/libjailbreak/src/primitives_IOSurface.m"
        for name in ("IOSurface_kalloc_16up", "IOSurface_kalloc_global", "IOSurface_kalloc_local"):
            implementation += function_source(path, name).replace("@available(iOS 16.0, *)", "fixture_modern") + "\n"
        for name in ("kalloc_with_options", "kalloc"):
            implementation += function_source("BaseBin/libjailbreak/src/primitives.c", name) + "\n"
        implementation += function_source("Packages/libkrw-provider/src/main.c", "krw_initializer")
        with tempfile.TemporaryDirectory(prefix="port-iosurface-result-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation,
                                         "tests/iosurface_allocation_result_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("17 allocation result cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
