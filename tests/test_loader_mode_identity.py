import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class LoaderModeIdentityTests(unittest.TestCase):
    def test_mode_changes_use_the_requesting_identity(self):
        path = "BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c"
        implementation = "\n".join(function_source(path, name) for name in
                                   ("roothide_domain_allowed", "roothide_set_dyld_patch"))
        with tempfile.TemporaryDirectory(prefix="port-mode-identity-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation,
                                         "tests/loader_mode_identity_tests.c", ("-U__arm64e__",))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("7 caller-identity cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
