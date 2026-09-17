import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class Palera1nServerTransportTests(unittest.TestCase):
    def test_helper_frame_validation_and_completion(self):
        path = "Application/Dopamine/Exploits/palera1n/exploit_server/main.m"
        source = (ROOT / path).read_text()
        header = ROOT / "Application/Dopamine/Exploits/palera1n/pipe_transport.h"
        implementation = (header.read_text() if header.exists() else "") + "\n"
        implementation += re.search(r"mach_port_t g_tfp0[^\n]*", source).group(0) + "\n"
        implementation += source[source.index("kern_return_t kread_buf("):source.index("kern_return_t kread_addr(")]
        implementation += re.search(r"enum SERVER_CMD \{.*?\};", source, re.DOTALL).group(0) + "\n"
        implementation += "#define SERVER_INPUT_FD 5\n#define SERVER_OUTPUT_FD 6\n"
        if "static int serve_requests(" in source:
            implementation += function_source(path, "serve_requests") + "\n"
        implementation += "#define main fixture_server_main\n" + function_source(path, "main") + "\n#undef main\n"
        cases = ["read", "write", "short-input", "short-output", "interrupted-input", "interrupted-output",
                 "header-truncated", "payload-truncated", "allocation-refused", "oversized", "address-wrap",
                 "partial-mach-read", "mach-read-failed", "zero-size", "eof", "unknown", "partial-command-stall",
                 "idle", "reply-closed"]
        flags = ["-DPALERA1N_IO_TIMEOUT_MS=200", "-DPALERA1N_REAP_TIMEOUT_MS=100"]
        with tempfile.TemporaryDirectory(prefix="palera1n-server-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation,
                                         "tests/palera1n_server_transport_tests.c", flags)
            failures = []
            for case in cases:
                result = run_fixture(executable, case)
                if result.returncode or "runtime error:" in result.stderr:
                    failures.append(f"{case}: {result.returncode}\n{result.stdout}{result.stderr}")
            self.assertFalse(failures, "\n".join(failures))
        print(f"Palera1n helper: {len(cases)} ordinary-pipe scenarios passed with all Mach operations replaced")


if __name__ == "__main__":
    unittest.main()
