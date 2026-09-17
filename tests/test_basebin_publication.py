import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class BasebinPublicationTests(unittest.TestCase):
    def test_hot_update_publication_errors_are_not_reported_as_success(self):
        implementation = function_source("BaseBin/libjailbreak/src/basebin_gen.m", "basebin_generate_internal")
        with tempfile.TemporaryDirectory(prefix="basebin-publication-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/basebin_publication_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in ("copy-failure", "missing-current", "success"):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
