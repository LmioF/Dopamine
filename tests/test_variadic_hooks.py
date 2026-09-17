import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, function_source, compile_fixture, run_fixture


class VariadicHookTests(unittest.TestCase):
    def test_fcntl_and_sandbox_hooks_forward_only_contract_arguments(self):
        springboard = (ROOT / "BaseBin/roothidehooks/springboard.x").read_text()
        start = springboard.index("static int fcntlCommandTakesArgument")
        end = springboard.index("@interface", start)
        fcntl_hook = springboard[start:end]
        fcntl_hook = fcntl_hook.replace("%hookf(int, fcntl,", "int fcntl_hook(", 1)
        fcntl_hook = fcntl_hook.replace("%orig", "TEST_FCNTL_ORIG")

        sandbox_source = (ROOT / "BaseBin/launchdhook/src/ipc_hook.c").read_text()
        sandbox_start = sandbox_source.index("int sandbox_check_by_audit_token_hook")
        sandbox_end = sandbox_source.index("\nvoid initIPCHooks", sandbox_start)
        sandbox_hook = sandbox_source[sandbox_start:sandbox_end]
        implementation = fcntl_hook + "\n" + sandbox_hook

        with tempfile.TemporaryDirectory(prefix="variadic-hooks-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/variadic_hooks_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
