import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class ServiceStartupTests(unittest.TestCase):
    def test_actual_startup_ordering_and_results(self):
        path = "BaseBin/jbctl/src/internal.m"
        source = (ROOT / path).read_text()
        start = source.index('else if (!strcmp(command, "startup"))')
        end = source.index('else if (!strcmp(command, "install_pkg"))', start)
        branch = source[start:end].strip()[len("else "):]
        helper = function_source(path, "jbctl_startup") if "static int jbctl_startup(" in source else ""
        implementation = helper + '\nstatic int run_startup(void)\n{\nconst char *command = "startup";\n' + branch + '\nreturn -1;\n}\n'
        with tempfile.TemporaryDirectory(prefix="service-startup-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/service_startup_tests.m", ("-fobjc-arc", "-framework", "Foundation"))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
