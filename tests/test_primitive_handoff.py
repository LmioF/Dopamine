import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class PrimitiveHandoffTests(unittest.TestCase):
    def test_recovery_propagates_acquisition_and_completion_failures(self):
        implementation = function_source("BaseBin/launchdhook/src/boomerang.c", "boomerang_recoverPrimitives")
        with tempfile.TemporaryDirectory(prefix="primitive-handoff-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), implementation, "tests/primitive_handoff_tests.c"
            )
            for scenario in ("acquire-fail", "done-fail", "success"):
                result = run_fixture(executable, scenario)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reexec_does_not_teardown_hookd_until_stash_succeeds(self):
        spawn = (ROOT / "BaseBin/launchdhook/src/spawn_hook.c").read_text()
        stash = spawn.index("boomerang_stashPrimitives()")
        teardown = spawn.index("hookd_provider_teardown()")
        self.assertLess(stash, teardown)
        self.assertRegex(spawn[stash:teardown], r"(?s)boomerang_stashPrimitives\(\).*?stashResult != 0")

    def test_stash_completion_wait_is_bounded(self):
        source = (ROOT / "BaseBin/launchdhook/src/boomerang.c").read_text()
        stash = source[source.index("int boomerang_stashPrimitives"):source.index("int boomerang_recoverPrimitives")]
        self.assertNotIn("DISPATCH_TIME_FOREVER", stash)
        self.assertIn("dispatch_time(DISPATCH_TIME_NOW", stash)
        self.assertIn("ETIMEDOUT", stash)
        self.assertRegex(stash, r"(?s)waitpid\(boomerangPid, NULL, WNOHANG\).*?kill\(boomerangPid, SIGKILL\)")

    def test_boomerang_process_propagates_primitive_and_done_failures(self):
        source = (ROOT / "BaseBin/boomerang/src/main.c").read_text()
        acquisition = source.index("jbclient_initialize_primitives_internal(false)")
        completion = source.index("jbclient_boomerang_done()", acquisition)
        self.assertRegex(
            source[acquisition:completion],
            r"(?s)jbclient_initialize_primitives_internal\(false\).*?!= 0.*?return -1",
        )
        self.assertRegex(
            source[completion:source.index("roothide_patch_proc", completion)],
            r"(?s)jbclient_boomerang_done\(\).*?!= 0.*?return -1",
        )


if __name__ == "__main__":
    unittest.main()
