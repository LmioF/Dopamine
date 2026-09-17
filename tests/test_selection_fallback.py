import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class SelectionFallbackTests(unittest.TestCase):
    def test_all_preference_types_recover_unavailable_selections(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOExploitManager.m").read_text()
        methods = []
        for selector in ("_findExploitWithIdentifier", "selectedKernelExploit", "selectedPACBypass", "selectedPPLBypass"):
            match = re.search(r"^- \(DOExploit \*\)" + selector + r"[^\n]*\n\{.*?^\}", source, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match)
            methods.append(match.group(0))
        with tempfile.TemporaryDirectory(prefix="port-preference-fixture-") as directory:
            executable = compile_fixture(pathlib.Path(directory), "\n".join(methods),
                                         "tests/selection_fallback_tests.m", ("-fobjc-arc", "-framework", "Foundation"))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("15 preference checks, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
