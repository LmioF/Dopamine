import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class MappableSlicesTests(unittest.TestCase):
    def test_old_and_new_arm64e_admission_on_both_hosts(self):
        with tempfile.TemporaryDirectory(prefix="port-mappable-slices-") as directory:
            executable = compile_fixture(pathlib.Path(directory),
                                         function_source("BaseBin/libjailbreak/src/signatures.c", "macho_is_mappable"),
                                         "tests/mappable_slice_tests.c", ("-fblocks", "-Wno-sign-compare"))
            for host in ("arm64", "arm64e"):
                with self.subTest(host=host):
                    result = run_fixture(executable, host)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
