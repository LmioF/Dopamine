import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class UpdateOffsetTests(unittest.TestCase):
    def test_hot_update_uses_upstream_sets_and_retains_roothide_globals(self):
        source = (ROOT / "BaseBin/launchdhook/src/update.m").read_text()
        body = source.split("void jbupdate_update_system_info(void)", 1)[1].split("// Before primitives are retrieved", 1)[0]
        with tempfile.TemporaryDirectory(prefix="wolf-update-offsets-") as directory:
            path = pathlib.Path(directory)
            (path / "update-under-test.h").write_text("void jbupdate_update_system_info(void)" + body)
            executable = path / "update_offset_tests"
            result = subprocess.run(
                ["xcrun", "clang", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
                 "-framework", "Foundation", "-I", str(path),
                 str(ROOT / "tests/update_offset_tests.m"), "-o", str(executable)],
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("boot-resolved roothide state passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
