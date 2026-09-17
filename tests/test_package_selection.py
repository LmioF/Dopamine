import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class PackageSelectionTests(unittest.TestCase):
    def test_actual_package_selection(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        constants = source[source.index("#define LIBKRW_DOPAMINE_BUNDLED_VERSION"):source.index("struct hfs_mount_args")]
        methods = []
        for name in ("installedVersionForPackageWithIdentifier", "shouldInstallPackage"):
            match = re.search(r"^- \([^\n]+\)" + name + r":[^\n]*\n\{.*?^\}", source, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            methods.append(match.group(0))
        implementation = constants + "\n@implementation DOBootstrapper\n" + "\n".join(methods) + "\n@end\n"
        with tempfile.TemporaryDirectory(prefix="package-selection-") as temporary:
            directory = pathlib.Path(temporary)
            executable = compile_fixture(
                directory, implementation, "tests/package_selection_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation",
                 "-I", str(ROOT / "Application/Dopamine/Extensions"),
                 str(ROOT / "Application/Dopamine/Extensions/NSString+Version.m")),
            )
            result = run_fixture(executable, str(directory / "status"))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bundled_provider_metadata_matches_control(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        bundled = re.search(r'#define LIBKRW_DOPAMINE_BUNDLED_VERSION @"([^"]+)"', source).group(1)
        control = (ROOT / "Packages/libkrw-provider/control").read_text()
        packaged = re.search(r"^Version: (.+)$", control, re.MULTILINE).group(1)
        self.assertEqual(bundled, packaged)


if __name__ == "__main__":
    unittest.main()
