import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class ForkHandshakeTests(unittest.TestCase):
    def test_actual_fork_handshake_rejects_incomplete_protocol(self):
        path = "BaseBin/forkfix/src/main.c"
        source = (ROOT / path).read_text()
        helpers = []
        for name in ("close_pipe_end", "wait_for_pipe", "read_protocol_byte", "write_protocol_byte"):
            if f"{name}(" in source:
                helpers.append(function_source(path, name))
        implementation = "\n".join(
            [
                "int childToParentPipe[2];",
                "int parentToChildPipe[2];",
                *helpers,
                function_source(path, "open_pipes"),
                function_source(path, "close_pipes"),
                function_source(path, "child_fixup"),
                function_source(path, "parent_fixup"),
                function_source(path, "forkfix___fork"),
            ]
        )
        scenarios = (
            "child-read-eof",
            "child-write-error",
            "child-eintr",
            "parent-read-eof",
            "parent-write-error",
            "parent-repair-error",
            "child-unused-ends",
            "parent-unused-ends",
        )
        with tempfile.TemporaryDirectory(prefix="fork-handshake-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary),
                implementation,
                "tests/fork_handshake_tests.c",
            )
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario)
                if result.returncode:
                    failures.append(
                        f"{scenario}: exit {result.returncode}\n{(result.stdout + result.stderr)[:1800]}"
                    )
            if failures:
                self.fail("\n".join(failures))


if __name__ == "__main__":
    unittest.main()
