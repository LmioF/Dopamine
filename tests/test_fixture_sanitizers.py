import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, run_fixture


class FixtureSanitizerTests(unittest.TestCase):
    def test_undefined_behavior_cannot_report_success(self):
        with tempfile.TemporaryDirectory(prefix="fixture-sanitizers-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), "", "tests/fixture_sanitizer_tests.c"
            )
            clean = run_fixture(executable, "clean")
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
            self.assertIn("fixture completed", clean.stdout)
            self.assertEqual(clean.stderr, "")

            overflow = run_fixture(executable, "overflow")
            self.assertIn("signed integer overflow", overflow.stderr)
            self.assertNotEqual(overflow.returncode, 0, overflow.stdout + overflow.stderr)
            self.assertNotIn("fixture completed", overflow.stdout)


if __name__ == "__main__":
    unittest.main()
