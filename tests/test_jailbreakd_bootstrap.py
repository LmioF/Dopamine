import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/libjailbreak/src/roothider/jailbreakd.c"


class JailbreakdBootstrapTests(unittest.TestCase):
    """Inspect the actual receiver without starting a privileged daemon."""

    @classmethod
    def setUpClass(cls):
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True,
        ).strip()
        cls.ir = {}
        with tempfile.TemporaryDirectory(prefix="roothide-bootstrap-") as directory:
            for architecture in ("arm64", "arm64e"):
                output = pathlib.Path(directory) / f"{architecture}.ll"
                result = subprocess.run(
                    [
                        "xcrun", "--sdk", "iphoneos", "clang", "-arch", architecture,
                        "-isysroot", sdk, "-miphoneos-version-min=15.0", "-fblocks",
                        "-O2", "-S", "-emit-llvm", "-I", str(ROOT / "BaseBin/ChOma/include"), "-idirafter",
                        str(ROOT / "BaseBin/_external/include"), str(SOURCE),
                        "-o", str(output),
                    ], text=True, capture_output=True,
                )
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                cls.ir[architecture] = output.read_text()

    def receiver(self, architecture):
        functions = re.findall(
            r"^define[^\n]*\{\n(.*?)^\}", self.ir[architecture],
            re.MULTILINE | re.DOTALL,
        )
        receivers = [body for body in functions if "@xpc_pipe_receive(" in body]
        self.assertEqual(len(receivers), 1)
        return receivers[0]

    def dispatch_offset(self, receiver):
        handler = re.search(r"(%\d+) = load ptr, ptr @gJailbreakdBootstrapHandler\b", receiver)
        self.assertIsNotNone(handler, "The bootstrap receiver must invoke its launchd handler")
        return receiver.index(f" {handler.group(1)}(")

    def test_bootstrap_dictionary_is_dispatched_not_aborted(self):
        for architecture in self.ir:
            with self.subTest(architecture=architecture):
                receiver = self.receiver(architecture)
                self.assertNotIn("@abort(", receiver)
                self.assertLess(receiver.index("@xpc_pipe_receive("), self.dispatch_offset(receiver))

    def test_dictionary_is_released_after_dispatch(self):
        for architecture in self.ir:
            with self.subTest(architecture=architecture):
                receiver = self.receiver(architecture)
                self.assertIn("@xpc_release(", receiver)
                self.assertLess(self.dispatch_offset(receiver), receiver.index("@xpc_release("))

    def test_bootstrap_uses_launchd_domain_permissions(self):
        source = (ROOT / "BaseBin/launchdhook/src/roothider.m").read_text()
        self.assertRegex(source, r"initJailbreakd\(firstLoad,\s*jailbreakd_bootstrap_dispatch\)")
        self.assertRegex(source, r"jailbreakd_bootstrap_dispatch\(xpc_object_t message\)\s*\{\s*return jbserver_received_xpc_message\(&gGlobalServer, message\);")
        header = (ROOT / "BaseBin/libjailbreak/src/roothider/jailbreakd.h").read_text()
        self.assertIn("int (*bootstrapHandler)(xpc_object_t)", header)

    def test_shared_client_object_does_not_link_the_server(self):
        for architecture, ir in self.ir.items():
            with self.subTest(architecture=architecture):
                self.assertNotIn("@jbserver_received_xpc_message(", ir)


if __name__ == "__main__":
    unittest.main()
