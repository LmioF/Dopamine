import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class TrustFileIdentityTests(unittest.TestCase):
    def test_reopened_descriptor_matches_caller_object(self):
        header = (ROOT / "BaseBin/libjailbreak/src/signatures.h").read_text()
        declarations = header[header.index("typedef enum"):header.index("typedef uint8_t cdhash_t")]
        implementation = declarations + "\n"
        implementation += function_source("BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c", "systemwide_trust_file")
        cases = ["unchanged", "replaced", "removed", "hardlink", "query-short", "query-failed",
                 "path-unterminated", "stat-failed", "device-mismatch", "inode-mismatch", "generation-mismatch",
                 "descriptor-reused", "recheck-failed", "local-duplicate", "without-attachment",
                 "source-file", "source-proc", "source-allocation", "replaced-file", "replaced-proc", "replaced-allocation"]
        with tempfile.TemporaryDirectory(prefix="trust-file-identity-") as temporary:
            directory = pathlib.Path(temporary)
            executable = compile_fixture(directory, implementation, "tests/trust_file_identity_tests.c")
            failures = []
            for case in cases:
                with tempfile.TemporaryDirectory(prefix="files-", dir=directory) as files:
                    result = run_fixture(executable, case, files)
                    if result.returncode or "runtime error:" in result.stderr:
                        failures.append(f"{case}: {result.returncode}\n{result.stdout}{result.stderr}")
            self.assertFalse(failures, "\n".join(failures))
        print(f"Trust file identity: {len(cases)} ordinary-file scenarios passed")


if __name__ == "__main__":
    unittest.main()
