import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class ProcessWriteTests(unittest.TestCase):
    def test_process_translation_dispatch_and_failures(self):
        with tempfile.TemporaryDirectory(prefix="port-process-write-") as directory:
            executable = compile_fixture(pathlib.Path(directory),
                                         function_source("BaseBin/libjailbreak/src/primitives.c", "proc_vwritebuf"),
                                         "tests/process_write_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("10 process-write dispatch cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
