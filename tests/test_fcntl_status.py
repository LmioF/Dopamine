import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class FcntlStatusTests(unittest.TestCase):
    def test_actual_hook_error_boundary(self):
        path = "BaseBin/dyldhook/src/lv_bypass.c"
        source = (ROOT / path).read_text()
        helper = function_source(path, "fcntl_trust_error") if "static int fcntl_trust_error(" in source else ""
        implementation = helper + "\n" + source[source.index("int HOOK(__fcntl)"):]
        with tempfile.TemporaryDirectory(prefix="fcntl-status-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/fcntl_status_tests.c", ("-I", str(ROOT / "BaseBin/ChOma/output/ios/include")))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
