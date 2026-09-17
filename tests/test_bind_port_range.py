import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class BindPortRangeTests(unittest.TestCase):
    def test_ipv4_ipv6_exhaustion_and_early_results(self):
        implementation = function_source("BaseBin/launchdhook/src/roothider.m", "new_bind")
        with tempfile.TemporaryDirectory(prefix="port-bind-range-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/bind_port_range_tests.c",
                ["-Wno-tautological-constant-out-of-range-compare"],
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("11 bind range cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
