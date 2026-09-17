import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class HookdExternalSafetyTests(unittest.TestCase):
    def test_branch_encoders_validate_full_width_displacement(self):
        implementation = "\n".join(
            [
                function_source("BaseBin/systemhook/src/common/hookd_external.c", "arm64_gen_b"),
                function_source("BaseBin/systemhook/src/common/hookd_external.c", "arm64_gen_bl"),
            ]
        )
        with tempfile.TemporaryDirectory(prefix="hookd-branch-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), implementation, "tests/hookd_external_branch_tests.c"
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_emitter_does_not_publish_branch_after_body_failure(self):
        implementation = function_source(
            "BaseBin/systemhook/src/common/hookd_external.c", "emit_hookd_svc_trampoline"
        )
        with tempfile.TemporaryDirectory(prefix="hookd-emitter-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), implementation, "tests/hookd_external_emitter_tests.c"
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_scanner_bounds_storage_and_propagates_emission_failure(self):
        implementation = function_source(
            "BaseBin/systemhook/src/common/hookd_external.c", "apply_hookd_syscall_patches"
        )
        with tempfile.TemporaryDirectory(prefix="hookd-scanner-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), implementation, "tests/hookd_external_scanner_tests.c"
            )
            for scenario in ("capacity", "emission-fail", "success"):
                result = run_fixture(executable, scenario)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_private_pthread_trampoline_checks_setup_and_pc_independence(self):
        source = (ROOT / "BaseBin/systemhook/src/common/hookd_external.c").read_text()
        self.assertIn("hookd_prologue_is_pc_independent", source)
        init = source[source.index("init_hookd_external_support"):]
        self.assertRegex(init, r"vm_allocate\([^;]+\);\s*if \(kr != KERN_SUCCESS\)")
        self.assertRegex(init, r"(?s)hookd_prologue_is_pc_independent\(.*?\).*?return ENOTSUP")
        self.assertRegex(init, r"(?s)litehook_hook_function\([^;]+\);\s*if \(kr != KERN_SUCCESS\)")


if __name__ == "__main__":
    unittest.main()
