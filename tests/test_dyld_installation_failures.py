import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class DyldInstallationFailureTests(unittest.TestCase):
    def test_dlsym_hook_installation_is_required(self):
        path = "BaseBin/systemhook/src/main.c"
        implementation = function_source(path, "init_dlsym_hook")
        for architecture, flags in (("arm64", ()), ("arm64e", ("-D__arm64e__=1",))):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory(prefix="dyld-dlsym-") as temporary:
                executable = compile_fixture(
                    pathlib.Path(temporary),
                    implementation,
                    "tests/dyld_dlsym_installation_tests.c",
                    flags,
                )
                for scenario in ("legacy", "modern", "missing", "legacy-failure", "modern-failure"):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_vtable_restore_failure_is_reported(self):
        for path, name in (
            ("BaseBin/systemhook/src/roothider_main.c", "hook_dyld_routine"),
            ("BaseBin/systemhook/src/main.c", "dyld_hook_routine"),
        ):
            with self.subTest(path=path):
                implementation = f"#define HOOK_CALL {name}\n" + function_source(path, name)
                with tempfile.TemporaryDirectory(prefix="dyld-vtable-") as temporary:
                    executable = compile_fixture(
                        pathlib.Path(temporary),
                        implementation,
                        "tests/dyld_vtable_failure_tests.c",
                    )
                    for scenario in ("writable-failure", "restore-failure", "success"):
                        result = run_fixture(executable, scenario)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_checkin_stops_after_required_loader_hook_failure(self):
        path = "BaseBin/systemhook/src/roothider_main.c"
        implementation = function_source(path, "roothide_init_with_checkin")
        with tempfile.TemporaryDirectory(prefix="dyld-checkin-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary),
                implementation,
                "tests/dyld_checkin_failure_tests.c",
            )
            for scenario in ("hook-failure", "hook-success", "not-required"):
                result = run_fixture(executable, scenario)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
