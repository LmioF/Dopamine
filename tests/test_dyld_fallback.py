import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/systemhook/src/roothider_main.c"


class DyldFallbackTests(unittest.TestCase):
    """Run the actual fallback entry points without modifying the host loader."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="roothide-dyld-fallback-")
        cls.addClassCleanup(cls.directory.cleanup)
        directory = pathlib.Path(cls.directory.name)
        source = SOURCE.read_text()
        wrappers = source.split("void* (*dyld_dlopen_orig)", 1)[1].split("int hook_dyld_routine(", 1)[0]
        if "int init_dyldhooks()" in source:
            init_signature = "int init_dyldhooks()"
        else:
            init_signature = "void init_dyldhooks()"
        initializer = source.split(init_signature, 1)[1].split("extern struct mach_header __dso_handle;", 1)[0]
        fixture = (ROOT / "tests/dyld_fallback_tests.c").read_text()
        fixture = fixture.replace("/* PRODUCTION_ENTRY_POINTS */", "void* (*dyld_dlopen_orig)" + wrappers + init_signature + initializer)
        path = directory / "dyld_fallback_tests.c"
        path.write_text(fixture)
        cls.binaries = {}
        for architecture, flags in (("arm64", []), ("arm64e", ["-D__arm64e__=1"])):
            binary = directory / f"dyld_fallback_tests_{architecture}"
            result = subprocess.run(
                ["xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 *flags, str(path), "-o", str(binary)], text=True, capture_output=True,
            )
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            cls.binaries[architecture] = binary

    def run_case(self, case):
        for architecture, binary in self.binaries.items():
            with self.subTest(architecture=architecture):
                result = subprocess.run([str(binary), case], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_legacy_layout_registers_all_four_entry_points(self):
        self.run_case("legacy")

    def test_gapis_layout_registers_all_four_entry_points(self):
        self.run_case("modern")

    def test_legacy_layout_takes_precedence(self):
        self.run_case("both")

    def test_missing_loader_does_not_dereference_null(self):
        self.run_case("missing")

    def test_legacy_registration_failure_is_propagated(self):
        self.run_case("legacy-failure")

    def test_modern_registration_failure_is_propagated(self):
        self.run_case("modern-failure")

    def test_dlopen_variants_preserve_arguments_and_noload(self):
        self.run_case("wrappers")


if __name__ == "__main__":
    unittest.main()
