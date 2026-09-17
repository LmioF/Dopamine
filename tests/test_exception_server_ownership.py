import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class ExceptionServerOwnershipTests(unittest.TestCase):
    def test_received_exception_rights_are_released_and_failures_are_replied(self):
        implementation = function_source("BaseBin/libjailbreak/src/roothider/exec_trace.m", "exception_server")
        with tempfile.TemporaryDirectory(prefix="exception-server-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/exception_server_ownership_tests.m",
                ("-Wno-unused-variable", "-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in ("pid-fail", "no-trace", "thread-state-fail", "exception-state-fail"):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
