import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class JbctlBarrierTests(unittest.TestCase):
    def test_actual_release_gate(self):
        path = "BaseBin/jbctl/src/main.m"
        source = (ROOT / path).read_text()
        start = source.index("\tif (argc > 2)")
        end = source.index("\n\tconst char *rootPath", start)
        helper = function_source(path, "wait_for_parent") if "static int wait_for_parent(" in source else ""
        implementation = helper + "\nstatic int run_gate(int argc, char **argv)\n{\n" + source[start:end] + "\nobservedArgc = argc; observedTerminator = argv[argc] == NULL; return 0;\n}\n"
        with tempfile.TemporaryDirectory(prefix="jbctl-barrier-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/jbctl_barrier_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
