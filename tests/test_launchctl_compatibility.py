import importlib.util
import pathlib
import struct
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("launchctl_compat", ROOT / "Packages/launchctl/compat.py")
COMPAT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPAT)
API = b"_launch_active_user_switch"


def load_commands(data):
    offset = 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, offset)
        yield command, offset
        offset += size


def removed_api_import(data):
    for command, offset in load_commands(data):
        if command == 0x80000034:
            base, size = struct.unpack_from("<II", data, offset + 8)
            _, _, imports, strings, count, form, compression = struct.unpack_from("<7I", data, base)
            if form != 1 or compression:
                raise AssertionError("The regression fixture's chained-import format changed")
            for index in range(count):
                slot = base + imports + index * 4
                value = struct.unpack_from("<I", data, slot)[0]
                start = base + strings + (value >> 9)
                end = data.index(0, start, base + size)
                if data[start:end] == API:
                    return bool(value & 0x100), slot
    raise AssertionError("Missing regression-fixture import")


class LaunchctlCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = subprocess.check_output([
            "tar", "-xOf", str(ROOT / "Application/Dopamine/Resources/bootstrap_1900.tar.zst"),
            "./usr/bin/launchctl",
        ])

    def test_removed_api_is_optional_in_runtime_imports(self):
        self.assertFalse(removed_api_import(self.original)[0])
        self.assertTrue(removed_api_import(COMPAT.patch_launchctl(self.original))[0])

    def test_userswitch_returns_enotsup_without_calling_removed_api(self):
        call_offset = 0xAFF8
        self.assertEqual(struct.unpack_from("<I", self.original, call_offset)[0] & 0xFC000000, 0x94000000)
        patched = COMPAT.patch_launchctl(self.original)
        self.assertEqual(struct.unpack_from("<I", patched, call_offset)[0], 0x528005A0)

    def test_roothide_path_rewriting_and_other_code_are_unchanged(self):
        patched = COMPAT.patch_launchctl(self.original)
        self.assertEqual(len(patched), len(self.original))
        self.assertEqual(patched[0xB8F0:0xCC54], self.original[0xB8F0:0xCC54])
        changes = [index for index, (a, b) in enumerate(zip(patched, self.original)) if a != b]
        self.assertGreater(len(changes), 0)
        self.assertLessEqual(len(changes), 6)

    def test_invalid_or_wrong_binary_is_rejected(self):
        for data in (b"", b"not a Mach-O", self.original[:512]):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                COMPAT.patch_launchctl(data)

    def test_patch_is_not_applied_twice(self):
        with self.assertRaises(ValueError):
            COMPAT.patch_launchctl(COMPAT.patch_launchctl(self.original))


class LaunchctlInstallationTests(unittest.TestCase):
    def test_active_finalization_updates_launchctl_before_setup_scripts(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        active = source.rsplit("- (NSError *)finalizeBootstrap", 1)[1]
        self.assertTrue("launchctl-roothide.deb" in active, "Active finalization omits the compatible launchctl package")
        self.assertLess(active.index("launchctl-roothide.deb"), active.index("/prep_bootstrap.sh"))
        self.assertIn("__builtin_available(iOS 19.0, *)", active)
        self.assertIn("1:1.1.1-2+dp3.1", source)

    def test_xcode_and_package_build_use_the_roothide_package(self):
        project = (ROOT / "Application/Dopamine.xcodeproj/project.pbxproj").read_text()
        self.assertTrue("../Packages/launchctl/launchctl-roothide.deb" in project, "Xcode does not bundle the roothide-compatible package")
        self.assertIn("-C launchctl package", (ROOT / "Packages/Makefile").read_text())


@unittest.skipUnless((ROOT / "Packages/launchctl/launchctl-roothide.deb").exists(), "Build the launchctl package first")
class LaunchctlPackageTests(unittest.TestCase):
    def test_package_layout_signature_and_runtime_imports(self):
        package = ROOT / "Packages/launchctl/launchctl-roothide.deb"
        fields = subprocess.check_output(["dpkg-deb", "-f", str(package), "Architecture", "Version"], text=True)
        self.assertIn("iphoneos-arm64e", fields)
        self.assertIn("1:1.1.1-2+dp3.1", fields)
        with tempfile.TemporaryDirectory(prefix="launchctl-package-") as directory:
            root = pathlib.Path(directory)
            subprocess.run(["dpkg-deb", "-x", str(package), directory], check=True)
            binary = root / "usr/bin/launchctl"
            self.assertTrue(removed_api_import(binary.read_bytes())[0])
            self.assertEqual((root / "bin/launchctl").resolve(), binary.resolve())
            self.assertFalse((root / "var/jb").exists())
            self.assertTrue((root / "usr/share/doc/launchctl/LICENSE").is_file())
            verification = subprocess.run(["codesign", "--verify", "--strict", str(binary)], capture_output=True, text=True)
            self.assertEqual(verification.returncode, 0, verification.stderr)


if __name__ == "__main__":
    unittest.main()
