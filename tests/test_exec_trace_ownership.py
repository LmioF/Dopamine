import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class ExecTraceOwnershipTests(unittest.TestCase):
    def test_attach_setup_failures_restore_state_and_release_owned_resources(self):
        implementation = function_source("BaseBin/libjailbreak/src/roothider/exec_trace.m", "execTraceProcess")
        with tempfile.TemporaryDirectory(prefix="exec-trace-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/exec_trace_ownership_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in ("success", "get-fail", "set-fail", "attach-fail"):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
