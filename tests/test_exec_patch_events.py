import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class ExecPatchEventTests(unittest.TestCase):
    def test_event_reader_survives_interrupted_and_failed_kevent_reads(self):
        implementation = function_source("BaseBin/libjailbreak/src/roothider/exec_patch.m", "event_handler")
        with tempfile.TemporaryDirectory(prefix="exec-patch-events-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/exec_patch_event_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in ("eintr", "error"):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
