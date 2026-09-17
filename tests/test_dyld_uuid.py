import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class DyldUUIDTests(unittest.TestCase):
    def test_binary_uuid_comparison_does_not_require_a_terminator(self):
        implementation = function_source("BaseBin/systemhook/src/common/common.c", "string_has_prefix")
        implementation += "\n" + function_source("BaseBin/systemhook/src/main.c", "parse_dyldhook_jbinfo")
        with tempfile.TemporaryDirectory(prefix="port-dyld-uuid-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation, "tests/dyld_uuid_tests.c",
                                         ("-I", str(ROOT / "BaseBin/dyldhook/src"), "-fno-sanitize-recover=all"))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("7 binary UUID/check-in parsing cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
