import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class AppVersionTests(unittest.TestCase):
    def test_existing_app_version_contract(self):
        with tempfile.TemporaryDirectory(prefix="app-version-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), "", "tests/version_tests.m",
                ("-fobjc-arc", "-framework", "Foundation",
                 str(ROOT / "Application/Dopamine/Extensions/NSString+Version.m")),
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertIn("10 version checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
