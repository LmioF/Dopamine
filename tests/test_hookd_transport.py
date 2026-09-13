import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/launchdhook/src/hookd_provider.c"
CLIENT_SOURCE = ROOT / "BaseBin/libjailbreak/src/jbclient_mach.c"


class HookdTransportTests(unittest.TestCase):
    """Check the actual transport without modifying executable pages on the host."""

    @classmethod
    def setUpClass(cls):
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True,
        ).strip()
        cls.ir = {}
        cls.client_ir = {}
        with tempfile.TemporaryDirectory(prefix="wolf-hookd-") as directory:
            include = pathlib.Path(directory) / "include"
            include.mkdir()
            (include / "libjailbreak").symlink_to(ROOT / "BaseBin/libjailbreak/src")
            for architecture in ("arm64", "arm64e"):
                output = pathlib.Path(directory) / f"{architecture}.ll"
                result = subprocess.run(
                    [
                        "xcrun", "--sdk", "iphoneos", "clang", "-arch", architecture,
                        "-isysroot", sdk, "-miphoneos-version-min=15.0", "-fblocks",
                        "-O2", "-S", "-emit-llvm", "-I", str(include),
                        "-I", str(ROOT / "BaseBin/ChOma/include"), "-idirafter",
                        str(ROOT / "BaseBin/_external/include"), str(SOURCE),
                        "-o", str(output),
                    ], text=True, capture_output=True,
                )
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                cls.ir[architecture] = output.read_text()
                result = subprocess.run(
                    [
                        "xcrun", "--sdk", "iphoneos", "clang", "-arch", architecture,
                        "-isysroot", sdk, "-miphoneos-version-min=15.0", "-fblocks",
                        "-O2", "-S", "-emit-llvm", "-I", str(include),
                        "-I", str(ROOT / "BaseBin/ChOma/include"), "-idirafter",
                        str(ROOT / "BaseBin/_external/include"), str(CLIENT_SOURCE),
                        "-o", str(output),
                    ], text=True, capture_output=True,
                )
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                cls.client_ir[architecture] = output.read_text()

    def transport(self, architecture):
        match = re.search(
            r"^define[^\n]*@launchd_hookd_send_msg\([^\n]*\{\n(.*?)^\}",
            self.ir[architecture], re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def exchange(self, ir, caller):
        if "@jb_mach_msg_exchange(" not in caller:
            return caller
        self.assertEqual(caller.count("@jb_mach_msg_exchange("), 1)
        self.assertNotIn("@mach_msg(", caller)
        match = re.search(
            r"^define[^\n]*@jb_mach_msg_exchange\([^\n]*\{\n(.*?)^\}",
            ir, re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def test_one_combined_send_and_receive(self):
        for architecture in self.ir:
            with self.subTest(architecture=architecture):
                body = self.exchange(self.ir[architecture], self.transport(architecture))
                self.assertNotIn("@mach_msg_overwrite(", body)
                calls = re.findall(r"@mach_msg\(([^\n]*)", body)
                self.assertEqual(len(calls), 1)
                self.assertRegex(calls[0], r"^ptr [^,]+, i32(?: noundef)? 3,")

    def test_reply_cleanup_stays_after_exchange(self):
        for architecture in self.ir:
            with self.subTest(architecture=architecture):
                body = self.transport(architecture)
                exchange = "@jb_mach_msg_exchange(" if "@jb_mach_msg_exchange(" in body else "@mach_msg("
                self.assertIn(exchange, body)
                self.assertLess(body.index(exchange), body.index("@mach_msg_destroy("))

    def test_native_roundtrip_and_send_error(self):
        implementation = SOURCE.read_text().split("static int launchd_hookd_send_msg", 1)[1]
        implementation = "static int launchd_hookd_send_msg" + implementation.split("\nvoid hookd_provider_init", 1)[0]
        with tempfile.TemporaryDirectory(prefix="wolf-hookd-native-") as directory:
            root = pathlib.Path(directory)
            (root / "transport-under-test.h").write_text(implementation)
            executable = root / "hookd_exchange_tests"
            result = subprocess.run(
                [
                    "xcrun", "--sdk", "macosx", "clang", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-g", "-I", str(root),
                    "-I", str(ROOT / "BaseBin/libjailbreak/src"),
                    str(ROOT / "tests/hookd_exchange_tests.c"), "-o", str(executable),
                ], text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("three delayed roundtrips and send failure passed", result.stdout)

    def client_transport(self, architecture):
        match = re.search(
            r"^define[^\n]*@jbclient_mach_send_msg\([^\n]*\{\n(.*?)^\}",
            self.client_ir[architecture], re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def test_client_exchange_does_not_resume_between_send_and_receive(self):
        for architecture in self.client_ir:
            with self.subTest(architecture=architecture):
                body = self.exchange(self.client_ir[architecture], self.client_transport(architecture))
                self.assertNotIn("@mach_msg_overwrite(", body)
                calls = re.findall(r"@mach_msg\(([^\n]*)", body)
                self.assertEqual(len(calls), 1)
                self.assertRegex(calls[0], r"^ptr [^,]+, i32(?: noundef)? 3,")

    def test_client_preserves_filtered_process_message_id(self):
        for architecture in self.client_ir:
            with self.subTest(architecture=architecture):
                self.assertIn("1073742030", self.client_transport(architecture))

    def test_client_cleanup_follows_completed_exchange(self):
        for architecture in self.client_ir:
            with self.subTest(architecture=architecture):
                body = self.client_transport(architecture)
                exchange = "@jb_mach_msg_exchange(" if "@jb_mach_msg_exchange(" in body else "@mach_msg("
                self.assertIn(exchange, body)
                self.assertLess(body.index(exchange), body.index("@mach_msg_destroy("))

    def test_native_client_roundtrip_and_send_error(self):
        implementation = CLIENT_SOURCE.read_text().split("kern_return_t jbclient_mach_send_msg", 1)[1]
        implementation = "kern_return_t jbclient_mach_send_msg" + implementation.split("\nint jbclient_mach_process_checkin", 1)[0]
        with tempfile.TemporaryDirectory(prefix="wolf-client-native-") as directory:
            root = pathlib.Path(directory)
            (root / "transport-under-test.h").write_text(implementation)
            executable = root / "jbclient_exchange_tests"
            result = subprocess.run(
                [
                    "xcrun", "--sdk", "macosx", "clang", "-fblocks", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-g", "-I", str(root),
                    "-I", str(ROOT / "BaseBin/libjailbreak/src"),
                    "-I", str(ROOT / "BaseBin/ChOma/include"),
                    "-idirafter", str(ROOT / "BaseBin/_external/include"),
                    str(ROOT / "tests/jbclient_exchange_tests.c"), "-o", str(executable),
                ], text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("client roundtrips and send failure passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
