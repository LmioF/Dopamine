import pathlib
import subprocess
import tarfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "BaseBin/roothidehooks/.theos/obj/roothidehooks.dylib"
PROVIDER_PATH = "fallback/CydiaSubstrate.framework/CydiaSubstrate"
PROVIDER = ROOT / "BaseBin/_external/basebin" / PROVIDER_PATH


class HookProviderCompatibilityTests(unittest.TestCase):
    def test_fallback_provider_exposes_the_dopamine3_hookd_adapter(self):
        for architecture in ("arm64", "arm64e"):
            with self.subTest(architecture=architecture):
                output = subprocess.check_output(
                    ["xcrun", "nm", "-arch", architecture, "-gU", str(PROVIDER)], text=True,
                )
                symbols = {fields[-1]: fields[-2] for line in output.splitlines()
                           if len(fields := line.split()) >= 3}
                self.assertEqual(symbols.get("_EKHookMemoryRaw"), "D",
                                 "iOS 26 needs the writable ElleKit hookd-adapter pointer")
                for name in ("_MSHookFunction", "_MSHookMessageEx", "_MSFindSymbol", "_MSGetImageByName"):
                    self.assertIn(name, symbols)

    @unittest.skipUnless((ROOT / "BaseBin/basebin.tar").is_file(), "Build BaseBin before checking its archive")
    def test_archive_contains_the_current_hook_provider(self):
        with tarfile.open(ROOT / "BaseBin/basebin.tar") as archive:
            self.assertEqual(archive.extractfile("basebin/" + PROVIDER_PATH).read(), PROVIDER.read_bytes())


@unittest.skipUnless(LIBRARY.is_file(), "Build BaseBin before checking packaged library dependencies")
class BasebinLinkageTests(unittest.TestCase):
    def test_roothide_library_resolves_without_a_lazy_jbroot_symlink(self):
        for architecture in ("arm64", "arm64e"):
            with self.subTest(architecture=architecture):
                output = subprocess.check_output(
                    ["xcrun", "otool", "-arch", architecture, "-L", str(LIBRARY)],
                    text=True,
                )
                dependencies = [line.strip().split(" (compatibility", 1)[0]
                                for line in output.splitlines()[2:]]
                self.assertIn("@loader_path/../usr/lib/libroothide.dylib", dependencies)
                self.assertFalse(any("/.jbroot/" in path for path in dependencies), output)
                self.assertIn("@loader_path/libjailbreak.dylib", dependencies)
                self.assertIn("@rpath/CydiaSubstrate.framework/CydiaSubstrate", dependencies)

    def test_bootstrap_contains_the_relative_roothide_dependency(self):
        result = subprocess.run(
            ["tar", "-tf", str(ROOT / "Application/Dopamine/Resources/bootstrap_1900.tar.zst"),
             "./usr/lib/libroothide.dylib"], text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("./usr/lib/libroothide.dylib", result.stdout)


if __name__ == "__main__":
    unittest.main()
