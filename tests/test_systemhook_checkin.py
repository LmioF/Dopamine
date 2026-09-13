import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/systemhook/src/main.c"


class SystemhookCheckinTests(unittest.TestCase):
    def test_fallback_uses_mach_checkin_before_consuming_extensions(self):
        source = SOURCE.read_text()
        initializer = source.split("__attribute__((constructor)) static void initializer(void)", 1)[1]
        self.assertNotIn("jbclient_process_checkin(", initializer)
        self.assertIn("systemhook_checkin()", initializer)
        self.assertLess(initializer.index("systemhook_checkin()"), initializer.index("consume_tokenized_sandbox_extensions("))

    def test_native_fallback_output_lifetime_and_failure(self):
        source = SOURCE.read_text()
        match = re.search(r"static int systemhook_checkin\(void\)\n\{.*?\n\}", source, re.DOTALL)
        self.assertIsNotNone(match, "The fallback must use the existing filtered-process Mach protocol")
        with tempfile.TemporaryDirectory(prefix="wolf-checkin-") as directory:
            root = pathlib.Path(directory)
            (root / "checkin-under-test.h").write_text(match.group(0))
            executable = root / "systemhook_checkin_tests"
            result = subprocess.run(
                [
                    "xcrun", "--sdk", "macosx", "clang", "-fblocks", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-g", "-I", str(root),
                    "-I", str(ROOT / "BaseBin/libjailbreak/src"),
                    "-I", str(ROOT / "BaseBin/ChOma/include"),
                    "-idirafter", str(ROOT / "BaseBin/_external/include"),
                    str(ROOT / "tests/systemhook_checkin_tests.c"), "-o", str(executable),
                ], text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("check-in outputs and failure preservation passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
