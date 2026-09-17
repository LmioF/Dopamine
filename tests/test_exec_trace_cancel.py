import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class ExecTraceCancelTests(unittest.TestCase):
    def test_cancel_signal_failure_has_defined_ownership(self):
        implementation = function_source("BaseBin/libjailbreak/src/roothider/exec_trace.m", "execTraceCancel")
        with tempfile.TemporaryDirectory(prefix="exec-trace-cancel-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/exec_trace_cancel_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in ("success", "gone", "denied"):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
