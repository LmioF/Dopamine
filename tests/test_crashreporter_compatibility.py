import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/libjailbreak/src/roothider/crashreporter.m"
ENTRY_POINTS = ("crashreporter_start", "crashreporter_pause", "crashreporter_resume")


class CrashReporterCompatibilityTests(unittest.TestCase):
    """Compile the actual reporter; host tests never register exception ports."""

    @classmethod
    def setUpClass(cls):
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True,
        ).strip()
        cls.ir = {}
        with tempfile.TemporaryDirectory(prefix="roothide-crashreporter-") as directory:
            for architecture in ("arm64", "arm64e"):
                for minimum in (15, 17):
                    output = pathlib.Path(directory) / f"{architecture}-ios{minimum}.ll"
                    result = subprocess.run(
                        [
                            "xcrun", "--sdk", "iphoneos", "clang", "-arch", architecture,
                            "-isysroot", sdk, f"-miphoneos-version-min={minimum}.0",
                            "-fobjc-arc", "-O2", "-S", "-emit-llvm", "-idirafter",
                            str(ROOT / "BaseBin/_external/include"), str(SOURCE),
                            "-o", str(output),
                        ],
                        text=True, capture_output=True,
                    )
                    if result.returncode:
                        raise RuntimeError(result.stdout + result.stderr)
                    cls.ir[architecture, minimum] = output.read_text()

    def body(self, architecture, minimum, function):
        match = re.search(
            rf"^define[^\n]*@{function}\([^\n]*\)[^\n]*\{{\n(.*?)^\}}",
            self.ir[architecture, minimum], re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"Missing compiled definition: {function}")
        return match.group(1)

    def test_ios17_and_later_entry_points_have_no_side_effects(self):
        for architecture in ("arm64", "arm64e"):
            for function in ENTRY_POINTS:
                with self.subTest(architecture=architecture, function=function):
                    body = self.body(architecture, 17, function)
                    self.assertNotRegex(body, r"\b(?:call|invoke|store|atomicrmw)\b")
                    expected = "ret i32 0" if function == "crashreporter_pause" else "ret void"
                    self.assertIn(expected, body)

    def test_ios15_deployment_retains_runtime_ios17_guard(self):
        for architecture in ("arm64", "arm64e"):
            for function in ENTRY_POINTS:
                with self.subTest(architecture=architecture, function=function):
                    body = self.body(architecture, 15, function)
                    self.assertRegex(body, r"@__isPlatformVersionAtLeast\([^\n]*\b17\b")
                    self.assertRegex(body, r"\bbr i1\b")

    def test_legacy_exception_reporting_is_preserved(self):
        for architecture in ("arm64", "arm64e"):
            with self.subTest(architecture=architecture):
                start = self.body(architecture, 15, "crashreporter_start")
                self.assertIn("@mach_port_allocate", start)
                self.assertIn("@sigaction", start)
                for function in ("crashreporter_pause", "crashreporter_resume"):
                    self.assertIn("@task_set_exception_ports", self.body(architecture, 15, function))


if __name__ == "__main__":
    unittest.main()
