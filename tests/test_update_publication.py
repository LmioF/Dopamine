import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class UpdatePublicationTests(unittest.TestCase):
    def test_partial_copy_and_destination_refusal_are_errors(self):
        implementation = function_source("BaseBin/launchdhook/src/update.m", "jbupdate_basebin")
        with tempfile.TemporaryDirectory(prefix="update-publication-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/update_publication_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in range(3):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, str(scenario))
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
