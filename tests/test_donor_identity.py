import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class DonorIdentityTests(unittest.TestCase):
    def test_actual_identity_sequence(self):
        source = (ROOT / "BaseBin/dyldhook/src/main.c").read_text()
        start = source.index("int credentialResult =")
        end = source.index("// if (gDyldHookLog)", start)
        implementation = "static int configure_identity(int uid, int ruid, int gid, int rgid, gid_t *groups, unsigned ngroups)\n{\n" + source[start:end] + "\nreturn credentialResult;\n}\n"
        with tempfile.TemporaryDirectory(prefix="donor-identity-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/donor_identity_tests.c", ("-Wno-sign-compare",))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
