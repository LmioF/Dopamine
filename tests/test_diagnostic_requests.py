import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class DiagnosticRequestTests(unittest.TestCase):
    def test_release_and_debug_request_outcomes(self):
        header = (ROOT / "BaseBin/libjailbreak/src/roothider/jailbreakd.h").read_text()
        enum = re.search(r"typedef enum \{.*?\} JBD_MESSAGE_ID;", header, re.DOTALL).group(0)
        implementation = enum + "\n" + function_source("BaseBin/jailbreakd/src/server.m", "jailbreakd_received_message")
        failures = []
        cases = ["unknown", "missing-id", "wrong-id", "not-dictionary", "no-reply", "receive-failure",
                 "log-valid", "log-missing", "log-wrong", "test-user", "test-root",
                 "test-negative", "test-overflow", "test-missing"]
        for enabled in (False, True):
            flags = ["-fobjc-arc", "-fblocks", "-framework", "Foundation"]
            if enabled:
                flags.append("-DENABLE_LOGS=1")
            with tempfile.TemporaryDirectory(prefix="diagnostic-requests-") as temporary:
                executable = compile_fixture(pathlib.Path(temporary), implementation,
                                             "tests/diagnostic_request_tests.m", flags)
                for case in cases:
                    result = run_fixture(executable, case)
                    if result.returncode or "runtime error:" in result.stderr:
                        failures.append(f"logs={enabled} {case}: exit {result.returncode}\n{result.stdout}{result.stderr}")
        self.assertFalse(failures, "\n".join(failures))
        print(f"Diagnostic requests: {len(cases) * 2} release/debug scenarios passed")


if __name__ == "__main__":
    unittest.main()
