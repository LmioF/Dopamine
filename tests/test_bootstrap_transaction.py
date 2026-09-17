import pathlib
import subprocess
import tempfile
import unittest

from port_review_test_support import ROOT


class BootstrapTransactionTests(unittest.TestCase):
    def test_fault_injection_recovers_root_pair_and_source_uses_transaction(self):
        sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
        clang = subprocess.check_output(["xcrun", "--sdk", "macosx", "--find", "clang"], text=True).strip()
        with tempfile.TemporaryDirectory(prefix="bootstrap-transaction-") as temporary:
            executable = pathlib.Path(temporary) / "bootstrap_transaction_tests"
            result = subprocess.run(
                [clang, "-isysroot", sdk, "-fobjc-arc", "-fblocks", "-fsanitize=address,undefined",
                 "-fno-sanitize-recover=all", "-framework", "Foundation",
                 str(ROOT / "tests/bootstrap_transaction_tests.m"), "-o", str(executable)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        bootstrapper = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        jailbreaker = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text()
        self.assertIn('#import "DOBootstrapTransaction.h"', bootstrapper)
        self.assertIn("RHBootstrapRecoverRerandomization", bootstrapper)
        self.assertIn("RHBootstrapRepairLegacyPair", bootstrapper)
        self.assertIn("RHBootstrapBeginRerandomization", bootstrapper)
        self.assertIn("if (![installationMarker writeToFile:", bootstrapper)

        remove_branch = jailbreaker.index("if (removeJailbreakEnabled)")
        prepare = jailbreaker.index("prepareBootstrap", remove_branch)
        later_remove = jailbreaker.find("if (removeJailbreakEnabled)", prepare)
        self.assertLess(remove_branch, prepare, "removal must bypass bootstrap preparation/re-randomization")
        self.assertEqual(later_remove, -1, "remove flow must not be deferred until after bootstrap preparation")


if __name__ == "__main__":
    unittest.main()
