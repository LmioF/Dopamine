import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class RecursiveTrustArchTransportTests(unittest.TestCase):
    def test_library_trust_sends_running_architecture(self):
        path = "BaseBin/libjailbreak/src/jbclient_roothide.c"
        implementation = function_source(path, "jbclient_copy_execution_arch_preferences")
        implementation += "\n" + function_source(path, "jbclient_trust_library_recurse")
        with tempfile.TemporaryDirectory(prefix="recursive-trust-arch-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation,
                                         "tests/recursive_trust_arch_transport_tests.c")
            for mode in ("caller", "main"):
                with self.subTest(mode=mode):
                    result = run_fixture(executable, mode)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
