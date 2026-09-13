import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/boomerang/src/main.c"


class BoomerangResumeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True,
        ).strip()
        cls.ir = {}
        with tempfile.TemporaryDirectory(prefix="boomerang-resume-") as directory:
            includes = pathlib.Path(directory) / "include"
            includes.mkdir()
            (includes / "libjailbreak").symlink_to(ROOT / "BaseBin/libjailbreak/src")
            for architecture in ("arm64", "arm64e"):
                output = pathlib.Path(directory) / f"{architecture}.ll"
                result = subprocess.run(
                    [
                        "xcrun", "--sdk", "iphoneos", "clang", "-arch", architecture,
                        "-isysroot", sdk, "-miphoneos-version-min=15.0", "-fblocks",
                        "-O1", "-S", "-emit-llvm", "-I", str(includes),
                        "-I", str(ROOT / "BaseBin/ChOma/include"), "-idirafter",
                        str(ROOT / "BaseBin/_external/include"), str(SOURCE),
                        "-o", str(output),
                    ], text=True, capture_output=True,
                )
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                cls.ir[architecture] = output.read_text()

    def main_body(self, architecture):
        match = re.search(r"^define[^\n]*@main\([^\n]*\{\n(.*?)^\}",
                          self.ir[architecture], re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_launchd_resume_uses_a_fresh_control_port(self):
        for architecture in self.ir:
            with self.subTest(architecture=architecture):
                body = self.main_body(architecture)
                patch = body.index("@unrestrict(")
                resume = body.find("@task_resume(", patch)
                self.assertGreater(resume, patch, "The launchd Mach suspension must be explicitly resumed")
                acquire = body.find("@task_for_pid(", patch)
                self.assertGreater(acquire, patch)
                self.assertLess(acquire, resume)
                self.assertGreater(body.find("@mach_port_deallocate(", resume), resume)

    def test_launchd_is_not_resumed_twice(self):
        for architecture in self.ir:
            with self.subTest(architecture=architecture):
                call = re.search(r"@unrestrict\(([^\n]+)\)", self.main_body(architecture))
                self.assertIsNotNone(call)
                self.assertRegex(call.group(1), r"i1[^,]*false$")

    def test_resume_failure_is_reported_before_serving_requests(self):
        source = SOURCE.read_text()
        self.assertIn("kr = task_resume(launchdTaskPort);", source)
        tail = source.split("kr = task_resume(launchdTaskPort);", 1)[1]
        self.assertRegex(tail, r"(?s)if \(kr != KERN_SUCCESS\).*?return -1;.*?dispatch_main\(\)")


if __name__ == "__main__":
    unittest.main()
