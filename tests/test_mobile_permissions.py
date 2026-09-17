import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class MobilePermissionTests(unittest.TestCase):
    def test_actual_permission_repair_stays_in_selected_tree(self):
        source = (ROOT / "BaseBin/libjailbreak/src/util.m").read_text()
        start = re.search(r"^(?:static )?void _JBFixMobilePermissions", source, re.MULTILINE)
        self.assertIsNotNone(start)
        implementation = source[start.start():].replace(
            '@"/var/mobile/Containers/Shared/AppGroup"', "gSecondaryContainer"
        )
        scenarios = (
            "normal", "mobile-link", "library-link", "selected-link", "nested-link",
            "file-link", "dangling-link", "link-cycle", "wrong-var", "secondary-link",
            "secondary-var-link", "primary-link", "invalid-root-name", "hardlink", "fifo",
            "already-owned", "ownership-refusal", "directory-open-refusal", "enumeration-refusal",
            "replacement-race", "descriptor-zero", "repeated", "missing-var",
            "primary-open-refusal", "container-open-refusal", "secondary-open-refusal",
            "var-open-refusal", "mobile-open-refusal", "metadata-refusal", "link-query-refusal",
            "child-stat-refusal", "file-open-refusal", "opened-file-stat-refusal",
            "different-device", "different-device-after-open", "non-directory-mobile",
            "replacement-after-open",
        )
        with tempfile.TemporaryDirectory(prefix="mobile-permissions-") as temporary:
            directory = pathlib.Path(temporary)
            executable = compile_fixture(
                directory, implementation, "tests/mobile_permissions_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in scenarios:
                with self.subTest(scenario=scenario):
                    root = directory / scenario
                    root.mkdir()
                    result = run_fixture(executable, scenario, str(root))
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("permission confinement passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
