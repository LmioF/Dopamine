import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def function_source(path: pathlib.Path, name: str) -> str:
    source = path.read_text()
    start = source.index(f"int {name}(")
    body = source.index("{", start)
    depth = 0
    for index in range(body, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise ValueError(f"Unclosed function: {name}")


class DyldVtableTests(unittest.TestCase):
    """Exercise both production patchers on actual read-only Mach VM mappings."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="roothide-vtable-")
        cls.addClassCleanup(cls.directory.cleanup)
        directory = pathlib.Path(cls.directory.name)
        patchers = "\n\n".join((
            function_source(ROOT / "BaseBin/systemhook/src/main.c", "dyld_hook_routine"),
            function_source(ROOT / "BaseBin/systemhook/src/roothider_main.c", "hook_dyld_routine"),
        ))
        fixture = (ROOT / "tests/dyld_vtable_tests.c").read_text()
        source = directory / "vtable.c"
        source.write_text(fixture.replace("/* PRODUCTION_PATCHERS */", patchers))
        cls.binary = directory / "vtable"
        result = subprocess.run(
            ["xcrun", "clang", "-O2", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-variable", str(source), "-o", str(cls.binary)],
            text=True, capture_output=True,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def run_case(self, case):
        for patcher in ("dyld", "roothide"):
            with self.subTest(patcher=patcher):
                result = subprocess.run(
                    [str(self.binary), patcher, case], text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_shared_readonly_mapping_gets_private_copy(self):
        self.run_case("shared")

    def test_private_mapping_keeps_its_original_backing_unchanged(self):
        self.run_case("private")

    def test_failed_protection_does_not_publish_a_hook(self):
        self.run_case("failure")

    def test_failed_restore_rolls_back_and_reports_failure(self):
        self.run_case("restore-failure")

    def test_null_interfaces_do_not_change_protection(self):
        self.run_case("null")


if __name__ == "__main__":
    unittest.main()
