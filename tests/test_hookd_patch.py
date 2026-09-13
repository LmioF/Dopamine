import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class HookdPatchTests(unittest.TestCase):
    def test_daemon_checkin_receive_buffer(self):
        source = (ROOT / "BaseBin/launchdhook/src/hookd_provider.c").read_text()
        implementation = "int hookd_start" + source.split("int hookd_start", 1)[1].split("\nstatic int launchd_hookd_send_msg", 1)[0]
        with tempfile.TemporaryDirectory(prefix="wolf-hook-checkin-") as directory:
            root = pathlib.Path(directory)
            (root / "checkin-under-test.h").write_text(implementation)
            executable = root / "hookd_checkin_tests"
            result = subprocess.run(
                [
                    "xcrun", "--sdk", "macosx", "clang", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter", "-fsanitize=address,undefined", "-g",
                    "-I", str(root), str(ROOT / "tests/hookd_checkin_tests.c"), "-o", str(executable),
                ], text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("receive buffer includes the Mach trailer", result.stdout)

    def test_target_threads_and_failure_cleanup(self):
        source = (ROOT / "BaseBin/hookd/src/main.c").read_text()
        match = re.search(r"int apply_hook\(.*?\n\{.*?\n\}", source, re.DOTALL)
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory(prefix="wolf-hook-patch-") as directory:
            root = pathlib.Path(directory)
            (root / "patch-under-test.h").write_text(match.group(0))
            executable = root / "hookd_patch_tests"
            result = subprocess.run(
                [
                    "xcrun", "--sdk", "macosx", "clang", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-fsanitize=address,undefined", "-g",
                    "-I", str(root), str(ROOT / "tests/hookd_patch_tests.c"), "-o", str(executable),
                ], text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("protection restoration, and error cleanup passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
