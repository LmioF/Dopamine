import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class EntitlementBlobTests(unittest.TestCase):
    def test_network_byte_order_and_returned_blob_extents(self):
        path = "BaseBin/systemhook/src/main.c"
        implementation = "\n".join(function_source(path, name) for name in
                                   ("copy_entitlements_xpc", "process_requires_hookd"))
        with tempfile.TemporaryDirectory(prefix="port-entitlement-blob-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation, "tests/entitlement_blob_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("11 entitlement blob cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
