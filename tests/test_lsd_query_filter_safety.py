import pathlib
import subprocess
import tempfile
import unittest

from port_review_test_support import ROOT


class LsdQueryFilterSafetyTests(unittest.TestCase):
    def test_query_filter_uses_copies_and_validates_correlated_arrays(self):
        source = (ROOT / "BaseBin/roothidehooks/lsd.x").read_text()
        self.assertIn("static NSArray *rhArrayByRemovingIndexes", source)
        self.assertIn("result = [result mutableCopy];", source)
        self.assertIn("rhSafeValueForKey", source)
        self.assertIn("rhSafeSetValueForKey", source)

        start = source.index("static NSArray *rhArrayByRemovingIndexes")
        end = source.index("%hook _LSQueryContext", start)
        helpers = source[start:end]

        with tempfile.TemporaryDirectory(prefix="lsd-query-filter-") as temporary:
            directory = pathlib.Path(temporary)
            implementation = directory / "implementation.h"
            implementation.write_text(helpers)
            executable = directory / "fixture"
            sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            clang = subprocess.check_output(["xcrun", "--sdk", "macosx", "--find", "clang"], text=True).strip()
            result = subprocess.run(
                [clang, "-isysroot", sdk, "-fobjc-arc", "-framework", "Foundation",
                 "-I", str(directory), str(ROOT / "tests/lsd_query_filter_safety_tests.m"), "-o", str(executable)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
