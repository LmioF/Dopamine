import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class Palera1nTransportTests(unittest.TestCase):
    def test_client_pipe_completion_and_helper_lifetime(self):
        path = "Application/Dopamine/Exploits/palera1n/palera1n.m"
        source = (ROOT / path).read_text()
        globals_source = re.search(r"pid_t serverPid[^\n]*\n.*?(?=#define SERVER_INPUT_FD)", source, re.DOTALL).group(0)
        protocol = source[source.index("enum SERVER_CMD"):source.index("/* csops  operations */")]
        header = ROOT / "Application/Dopamine/Exploits/palera1n/pipe_transport.h"
        implementation = (header.read_text() if header.exists() else "") + "\n"
        implementation += globals_source + "\n"
        implementation += function_source("BaseBin/libjailbreak/src/roothider/common.m", "wait_for_exit") + "\n"
        implementation += protocol + "\n" + function_source(path, "check_server") + "\n"
        cases = ["read-full", "write-full", "read-short", "write-short", "read-interrupted", "write-interrupted",
                 "read-eof", "payload-short", "result-short", "write-result-short", "partial-write-error", "zero-write",
                 "stall", "slide-full", "slide-short", "slide-stall", "server-error", "read-after-error", "concurrent",
                 "stop-ok", "stop-stall", "stop-interrupted", "check-ok", "check-stall", "check-persona-refused",
                 "check-init-refused", "check-spawn-refused", "check-invalid-pid", "zero-length", "bad-buffer",
                 "address-wrap", "large-read", "large-write"]
        flags = ["-fblocks", "-DPALERA1N_IO_TIMEOUT_MS=200", "-DPALERA1N_REAP_TIMEOUT_MS=100"]
        with tempfile.TemporaryDirectory(prefix="palera1n-transport-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation,
                                         "tests/palera1n_transport_tests.c", flags)
            failures = []
            for case in cases:
                result = run_fixture(executable, case)
                if result.returncode or "runtime error:" in result.stderr:
                    failures.append(f"{case}: {result.returncode}\n{result.stdout}{result.stderr}")
            self.assertFalse(failures, "\n".join(failures))
        print(f"Palera1n client: {len(cases)} ordinary-pipe and nonprivileged-child scenarios passed")


if __name__ == "__main__":
    unittest.main()
