import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/libjailbreak/src/util.c"


class CredentialHelperTests(unittest.TestCase):
    def test_persona_client_does_not_resume_after_failure(self):
        source = (ROOT / "BaseBin/systemhook/src/common/common.c").read_text()
        start = source.index("if (r == 0 && childPid > 0 && (personaFixUid == 0 || personaFixGid == 0))")
        end = source.index("\n}\n", start)
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static int rpc, resumes, kills, waits, resumeError;
static int jbclient_persona_fix(int pid, int uid, int gid) {
    assert(pid == 42 && uid == 0 && gid == 0); return rpc;
}
static int send_signal(int pid, int sig) {
    assert(pid == 42);
    if (sig == SIGCONT) { resumes++; if (resumeError) { errno = ESRCH; return -1; } }
    else { assert(sig == SIGKILL); kills++; }
    return 0;
}
static pid_t reap(pid_t pid, int *status, int flags) {
    (void)status; (void)flags; assert(pid == 42); waits++; return pid;
}
#define kill send_signal
#define waitpid reap
static int finish(int r, bool personaFixNeedsResume) {
    int childPid = 42, personaFixUid = 0, personaFixGid = 0;
BODY
}
int main(void) {
    rpc = -1;
    assert(finish(0, true) == EPERM);
    assert(kills == 1 && resumes == 0 && waits == 1);
    rpc = 0; kills = resumes = waits = 0;
    assert(finish(0, false) == 0 && resumes == 0 && kills == 0);
    assert(finish(0, true) == 0 && resumes == 1 && kills == 0);
    resumes = 0; resumeError = 1;
    assert(finish(0, true) == ESRCH && resumes == 1 && kills == 1 && waits == 1);
}
'''.replace("BODY", source[start:end])
        with tempfile.TemporaryDirectory(prefix="wolf-persona-") as directory:
            file = pathlib.Path(directory) / "persona.c"
            file.write_text(harness)
            executable = file.with_suffix("")
            result = subprocess.run(["xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", str(file), "-o", str(executable)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_donor_does_not_acknowledge_failed_identity_changes(self):
        source = (ROOT / "BaseBin/dyldhook/src/main.c").read_text()
        body = source.split("if (fd == -1) return;", 1)[1].split('__asm("b .");', 1)[0]
        harness = r'''
#include <assert.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>
static int call, failing;
static unsigned char marker;
static int change(void) { return ++call == failing ? -1 : 0; }
static ssize_t record(int fd, const void *data, size_t size) {
    assert(fd == 3 && size == 1); marker = *(const unsigned char *)data; return 1;
}
#define setgid(...) change()
#define setregid(...) change()
#define setgroups(...) change()
#define setuid(...) change()
#define setreuid(...) change()
#define write record
static void donor(void) {
    int fd = 3;
    gid_t groups[NGROUPS_MAX] = {0};
BODY
}
int main(void) {
    for (failing = 0; failing <= 7; failing++) {
        call = 0; marker = 0;
        donor();
        assert((marker == 0x42) == (failing == 0));
    }
}
'''.replace("BODY", body)
        with tempfile.TemporaryDirectory(prefix="wolf-donor-") as directory:
            root = pathlib.Path(directory)
            file = root / "donor.c"
            file.write_text(harness)
            output = root / "donor"
            result = subprocess.run(["xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare", str(file), "-o", str(output)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(output)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_preparation_reply_and_failure_cleanup(self):
        source = SOURCE.read_text()
        start = source.index("int target_proc_with_ucred(")
        end = source.index("\nint proc_ucred_update_content(", start)
        with tempfile.TemporaryDirectory(prefix="wolf-credential-") as directory:
            root = pathlib.Path(directory)
            (root / "helper-under-test.h").write_text(source[start:end])
            executable = root / "credential_helper_tests"
            result = subprocess.run(
                [
                    "xcrun", "--sdk", "macosx", "clang", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-fsanitize=address,undefined", "-g",
                    "-I", str(root), str(ROOT / "tests/credential_helper_tests.c"),
                    "-o", str(executable),
                ], text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("credential helper preparation and failure cleanup passed", result.stdout)

    def test_helper_spawn_avoids_recursive_injection(self):
        source = (ROOT / "BaseBin/launchdhook/src/roothider.m").read_text()
        function = source.split("int roothide_launchd___posix_spawn_prehook(", 1)[1]
        self.assertRegex(
            function,
            r'if\s*\([^\n]*envbuf_getenv\([^\n]*"DYLD_HOOK_SETUID"[^\n]*\)\s*\{\s*return __posix_spawn_orig_wrapper\(',
        )
        self.assertLess(function.index('"DYLD_HOOK_SETUID"'), function.index("isBlacklistedPath("))

    def test_both_credential_callers_propagate_failure(self):
        source = (ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c").read_text()
        calls = re.findall(r"if\s*\(proc_ucred_update_content\([^;]+?\)\s*!=\s*0\)\s*(?:\{\s*)?return -1;", source)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
