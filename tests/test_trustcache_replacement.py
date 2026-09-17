import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, function_source, compile_fixture, run_fixture


class TrustcacheReplacementTests(unittest.TestCase):
    def test_replacement_allocation_failure_preserves_existing_cache(self):
        implementation = function_source("BaseBin/libjailbreak/src/trustcache.c", "trustcache_file_upload")
        with tempfile.TemporaryDirectory(prefix="trustcache-replacement-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/trustcache_replacement_tests.c", ("-fblocks",))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
