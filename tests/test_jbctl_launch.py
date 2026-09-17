import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class JbctlLaunchTests(unittest.TestCase):
    def test_actual_launch_lifecycle(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text()
        match = re.search(r"^- \(int\)spawnJbctlAsRootWithArgs:[^\n]*\n\{.*?^\}", source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        scenarios = (
            "modern", "double-digit", "legacy", "no-version", "spawn-failure", "legacy-spawn-failure",
            "file-actions-failure", "attributes-failure", "pipe-failure", "dup-failure", "close-action-failure",
            "flags-failure", "nosigpipe-failure", "write-failure", "write-zero", "write-interrupted",
            "privilege-refusal", "invalid-pid", "legacy-resume-failure", "wait-status", "read-fd-three",
            "write-fd-three", "allocation-one", "allocation-three", "allocation-six",
        )
        with tempfile.TemporaryDirectory(prefix="jbctl-launch-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary), match.group(0), "tests/jbctl_launch_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation", "-I",
                 str(ROOT / "Application/Dopamine/Extensions"),
                 str(ROOT / "Application/Dopamine/Extensions/NSString+Version.m")),
            )
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario)
                if result.returncode:
                    failures.append(f"{scenario}: exit {result.returncode}\n{(result.stdout + result.stderr)[:1400]}")
            self.assertFalse(failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
