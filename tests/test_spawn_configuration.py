import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class SpawnConfigurationTests(unittest.TestCase):
    def test_actual_configuration_and_enumeration(self):
        source = (ROOT / "BaseBin/systemhook/src/common/common.c").read_text()
        header = (ROOT / "BaseBin/systemhook/src/common/common.h").read_text()
        enum = re.search(r"typedef enum\s*\{.*?\} kSpawnConfig;", header, re.DOTALL).group(0)
        end = source.index("static int copy_spawn_attributes") if "static int copy_spawn_attributes" in source else source.index("static int spawn_exec_hook_common")
        implementation = enum + "\n" + source[source.index("bool string_has_prefix"):end]
        ownership = "#define CONFIG_COPY_OWNED 1\n#define config_value jbuserconfig_copy_value\n" if "jbuserconfig_copy_value(" in source else "#define CONFIG_COPY_OWNED 0\n#define config_value jbuserconfig_get_value\n"
        scenarios = (
            "nested", "stop", "null-string", "allocation-refusal", "initial-invalid", "empty",
            "not-dictionary", "non-string-entry", "valid", "preserve-on-failed-reload", "retry-failed-reload",
            "same-timestamp-replacement", "older-timestamp-replacement", "retained-value", "missing-file",
            "mapping-failure", "concurrent-readers", "changed-during-read", "partial-read", "interrupted-read",
        )
        with tempfile.TemporaryDirectory(prefix="spawn-configuration-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), ownership + implementation, "tests/spawn_configuration_tests.c", ("-fblocks", "-pthread", "-fno-sanitize-recover=all"))
            failures = []
            for scenario in scenarios:
                result = run_fixture(executable, scenario, temporary)
                if result.returncode:
                    failures.append(f"{scenario}: exit {result.returncode}\n{(result.stdout + result.stderr)[:1400]}")
            self.assertFalse(failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
