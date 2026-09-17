import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class FcntlOutputTests(unittest.TestCase):
    def test_actual_signature_command_extents(self):
        path = "BaseBin/dyldhook/src/lv_bypass.c"
        source = (ROOT / path).read_text()
        helper = function_source(path, "fcntl_trust_error") if "static int fcntl_trust_error(" in source else ""
        implementation = helper + "\n" + source[source.index("int HOOK(__fcntl)"):]
        scenarios = (
            "return-legacy", "return-full", "info-input-only", "info-full", "info-future", "file-legacy",
            "proc-legacy", "return-rpc-error", "info-rpc-error", "return-retry-error", "info-retry-error",
            "initial-kernel-success", "info-zero-advertised", "info-short-advertised",
        )
        with tempfile.TemporaryDirectory(prefix="fcntl-outputs-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/fcntl_output_tests.c", ("-I", str(ROOT / "BaseBin/ChOma/output/ios/include")))
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario)
                if result.returncode:
                    failures.append(f"{scenario}: exit {result.returncode}\n{(result.stdout + result.stderr)[:1700]}")
            if failures:
                self.fail("\n".join(failures))


if __name__ == "__main__":
    unittest.main()
