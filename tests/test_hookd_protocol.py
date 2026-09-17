import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class HookdProtocolTests(unittest.TestCase):
    def test_actual_client_protocol(self):
        source = (ROOT / "BaseBin/libjailbreak/src/hookd.c").read_text()
        implementation = re.sub(r"^#include[^\n]*\n", "", source, flags=re.MULTILINE)
        scenarios = (
            "hook", "fixup", "mixed", "missing-hook", "missing-fixup", "extra-hook", "extra-fixup",
            "wrong-kind", "short-reply", "long-reply", "reply-overflow", "reply-error", "result-overflow",
            "transport-error", "negative-hooks", "negative-fixups", "null-hooks", "null-fixups",
            "null-hook-results", "null-fixup-results", "null-data", "huge-data", "large-batch",
            "odd-payloads", "empty", "zero-payload",
        )
        with tempfile.TemporaryDirectory(prefix="hookd-client-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/hookd_protocol_tests.c", ("-Wno-sign-compare", "-fno-sanitize-recover=all"))
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario)
                if result.returncode:
                    failures.append(f"{scenario}: exit {result.returncode}\n{(result.stdout + result.stderr)[:1300]}")
            self.assertFalse(failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
