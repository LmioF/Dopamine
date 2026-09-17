import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class SpawnAttributeOwnershipTests(unittest.TestCase):
    def test_actual_shared_spawn_wrappers(self):
        path = "BaseBin/systemhook/src/common/common.c"
        source = (ROOT / path).read_text()
        header = (ROOT / "BaseBin/systemhook/src/common/common.h").read_text()
        enum = re.search(r"typedef enum\s*\{.*?\} kSpawnConfig;", header, re.DOTALL).group(0)
        names = ["spawn_exec_hook_common", "posix_spawn_hook_shared", "execve_hook_shared"]
        if "static int copy_spawn_attributes(" in source:
            names.insert(0, "copy_spawn_attributes")
        implementation = enum + "\n" + "\n".join(function_source(path, name) for name in names)
        implementation = implementation.replace("__builtin_available(iOS 17.6, *)", "fixtureModern")
        scenarios = (
            "reused", "interleaved", "spawn-failure", "persona-failure", "resume-failure",
            "caller-suspended", "legacy", "already-root", "no-persona", "setexec", "flags-failure",
            "getflags-failure", "allocation-one", "allocation-two", "jetsam-overflow", "jetsam-infinite",
            "descriptor-persona", "short-attributes", "short-persona", "execve", "null-path",
        )
        with tempfile.TemporaryDirectory(prefix="spawn-attributes-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/spawn_attribute_ownership_tests.c", ("-fblocks", "-Wno-unused-label"))
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario)
                if result.returncode:
                    failures.append(f"{scenario}: exit {result.returncode}\n{(result.stdout + result.stderr)[:1500]}")
            self.assertFalse(failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
