import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DyldDispatchTests(unittest.TestCase):
    """Validate 23A341 dispatch code and keep loader tables read-only."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="roothide-dyld-dispatch-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = pathlib.Path(cls.directory.name) / "dispatch_tests"
        result = subprocess.run(
            ["xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-Ddlsym=dispatch_test_dlsym",
             "-Wno-unused-variable", "-I", str(ROOT / "BaseBin/systemhook/src"),
             "-I", str(ROOT / "BaseBin/_external/modules/litehook/src"),
             str(ROOT / "tests/dyld_dispatch_tests.c"),
             str(ROOT / "BaseBin/systemhook/src/dyld_dispatch.c"),
             "-o", str(cls.binary)], text=True, capture_output=True,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_all_five_captured_stubs_preserve_argument_setup(self):
        self.run_case("captured")

    def test_changed_or_truncated_stubs_are_not_patched(self):
        self.run_case("changed")

    def test_wrong_global_salt_and_invalid_arguments_are_rejected(self):
        self.run_case("invalid")

    def test_runtime_patcher_keeps_the_table_readonly(self):
        self.run_case("runtime")

    def test_backend_errors_propagate_with_a_valid_original(self):
        self.run_case("backend-failure")

    def test_public_exports_do_not_require_private_local_symbols(self):
        self.run_case("exports-only")

    def test_dlsym_uses_the_same_dispatch_backend(self):
        source = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        self.assertIn('dyld_hook_dispatch(gAPIsPtr, "_dlsym", 2, 16,', source)
        self.assertIn('(void **)&dyld_dlsym_orig, 0x839D)', source)


if __name__ == "__main__":
    unittest.main()
