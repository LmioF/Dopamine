import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class ThreadStartOwnershipTests(unittest.TestCase):
    def test_delayed_starts_and_creation_failure_ownership(self):
        path = "BaseBin/systemhook/src/common/hookd_external.c"
        source = (ROOT / path).read_text()
        preceding = function_source(path, "find_frida_text")
        start = source.index(preceding) + len(preceding)
        end = source.index("void *pthread_handler_hook(", start)
        declarations = source[start:end]
        original = re.search(r"int \(\*_pthread_create_orig\)\([^;]+;", source, re.DOTALL).group(0)
        implementation = declarations + "\n" + original + "\n"
        implementation += "\n".join(function_source(path, name) for name in
                                     ("pthread_handler_hook", "_pthread_create_hook"))
        with tempfile.TemporaryDirectory(prefix="port-thread-start-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation,
                                         "tests/thread_start_ownership_tests.c", ["-fblocks"])
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("7 thread-start ownership cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
