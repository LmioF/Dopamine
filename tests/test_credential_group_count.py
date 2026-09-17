import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class CredentialGroupCountTests(unittest.TestCase):
    def test_actual_sender_and_donor_preserve_group_count(self):
        util = "BaseBin/libjailbreak/src/util.c"
        source = (ROOT / util).read_text()
        counted = "int target_proc_with_ucred_counted(" in source
        sender = function_source(util, "target_proc_with_ucred_counted" if counted else "target_proc_with_ucred")
        donor = (ROOT / "BaseBin/dyldhook/src/main.c").read_text()
        start = donor.index('if (_simple_getenv(envp, "DYLD_HOOK_SETUID") != NULL)')
        end = donor.index('// If DYLD_INSERT_LIBRARIES is not set', start)
        branch = donor[start:end].replace('__asm("b .");', 'return;')
        parser = function_source("BaseBin/dyldhook/src/main.c", "parse_credential_number") if counted else ""
        implementation = '#define HAS_COUNTED_SENDER ' + str(int(counted)) + '\n' + parser + '\nstatic void run_donor(int argc, char **argv)\n{\nchar *envp[] = {NULL};\n' + branch + '\n}\n' + sender
        scenarios = ("one-zero-tail", "two-stale-tail", "maximum", "empty", "oversized", "null-groups", "wrong-primary", "wire-missing-count", "wire-bad-count", "wire-short-groups")
        with tempfile.TemporaryDirectory(prefix="credential-groups-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/credential_group_count_tests.c", ("-Wno-sign-compare",))
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario)
                if result.returncode or "runtime error:" in result.stderr:
                    failures.append(f"{scenario}: {result.returncode}\n{(result.stdout + result.stderr)[:1200]}")
            if failures:
                self.fail("\n".join(failures))

    def test_actual_counted_kernel_reader(self):
        source = (ROOT / "BaseBin/libjailbreak/src/util.c").read_text()
        self.assertTrue("int ucred_read_groups(" in source, "kernel groups need an explicit count reader")
        implementation = function_source("BaseBin/libjailbreak/src/util.c", "ucred_read_groups") + "\n"
        implementation += function_source("BaseBin/libjailbreak/src/util.c", "proc_ucred_update_content")
        with tempfile.TemporaryDirectory(prefix="credential-group-reader-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/credential_group_reader_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("runtime error:", result.stderr)
            print(result.stdout.strip())

    def test_counted_callers_and_legacy_entrypoint(self):
        source = (ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c").read_text()
        self.assertEqual(source.count("ucred_read_groups("), 2)
        self.assertEqual(source.count("proc_ucred_update_content_counted("), 2)
        legacy = function_source("BaseBin/libjailbreak/src/util.c", "proc_ucred_update_content")
        self.assertIn("ucred_read_groups(", legacy)
        self.assertIn("proc_ucred_update_content_counted(", legacy)


if __name__ == "__main__":
    unittest.main()
