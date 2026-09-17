import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class DyldPatchPublicationTests(unittest.TestCase):
    def test_patch_requires_symbol_uuid_and_successful_writes(self):
        implementation = function_source("BaseBin/libjailbreak/src/basebin_gen.m", "apply_dyld_patch")
        with tempfile.TemporaryDirectory(prefix="dyld-patch-publication-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/dyld_patch_publication_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in range(6):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, str(scenario))
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
