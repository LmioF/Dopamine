import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class RestartProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="port-restart-fixture-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.executable = compile_fixture(
            pathlib.Path(cls.directory.name),
            function_source("BaseBin/libjailbreak/src/util.c", "killall"),
            "tests/restart_process_tests.c",
        )

    def test_capacity_and_failure_paths(self):
        for mode in ("long-record", "allocation-refused", "process-allocation-refused",
                     "query-refused", "truncated", "unterminated", "oversized-result", "invalid-argmax",
                     "null-path", "empty-table", "process-query-refused", "process-fill-refused",
                     "oversized-process-result", "negative-pid", "unmatched", "short-record",
                     "argmax-refused", "truncated-argmax", "negative-argmax", "reused-buffer"):
            with self.subTest(mode=mode):
                result = run_fixture(self.executable, mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
