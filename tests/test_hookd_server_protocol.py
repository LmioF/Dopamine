import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class HookdServerProtocolTests(unittest.TestCase):
    def test_actual_server_frame_and_ownership(self):
        implementation = function_source("BaseBin/hookd/src/main.c", "server_loop")
        scenarios = (
            "mixed", "hook-only", "fixup-only", "odd-payloads", "empty", "repeated",
            "send-error", "receive-error", "task-error", "buffer-allocation-refused",
            "reply-allocation-refused", "short-message", "long-message", "complex-message",
            "offset-outside", "reversed-offsets", "short-hook", "long-hook", "zero-hook",
            "partial-fixup", "short-trailer", "long-trailer", "wrong-trailer", "wrong-caller",
        )
        with tempfile.TemporaryDirectory(prefix="hookd-server-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), implementation, "tests/hookd_server_protocol_tests.c",
                ("-Wno-sign-compare", "-fno-sanitize-recover=all"),
            )
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario)
                if result.returncode:
                    failures.append(f"{scenario}: exit {result.returncode}\n{(result.stdout + result.stderr)[:1600]}")
            self.assertFalse(failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
