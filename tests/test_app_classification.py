import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class AppClassificationTests(unittest.TestCase):
    def test_checkin_classifies_canonical_paths_and_respects_preference(self):
        helpers = "BaseBin/libjailbreak/src/roothider/common.m"
        implementation = "\n".join(function_source(helpers, name) for name in
                                   ("string_has_prefix", "getAppUUIDPath", "isRemovableBundlePath", "isSubPathOf"))
        checkin = function_source("BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c",
                                  "systemwide_process_checkin")
        start = checkin.rindex("bool fullyDebugged = false;")
        end = checkin.index("*fullyDebuggedOut = fullyDebugged;", start) + len("*fullyDebuggedOut = fullyDebugged;")
        implementation += ("\nstatic bool fixture_fully_debugged(const char *procPath)\n{\n"
                           "bool result = false; bool *fullyDebuggedOut = &result;\n" +
                           checkin[start:end] + "\nreturn result;\n}\n")
        with tempfile.TemporaryDirectory(prefix="port-app-classification-") as directory:
            root = pathlib.Path(directory).resolve()
            hidden = root / ".jbroot-fixture/Applications/Sileo.app/Sileo"
            normal = root / "containers/01234567-89ab-cdef-0123-456789abcdef/App.app/App"
            sibling = root / ".jbroot-fixture/ApplicationsOther/App.app/App"
            tool = root / "tools/tool"
            for path in (hidden, normal, sibling, tool):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            alias = root / "alias"
            alias.symlink_to(hidden)
            redirected = hidden.parent / "outside"
            redirected.symlink_to(tool)
            app_root = hidden.parents[1]
            paths = [(hidden, True), (alias, True), (normal, True), (sibling, False),
                     (app_root, False), (root / "missing", False), (tool, False), (redirected, False)]
            executable = compile_fixture(
                root, implementation, "tests/app_classification_tests.c",
                [f'-DAPP_PATH_PREFIX="{root}/containers/"', "-Wno-misleading-indentation"],
            )
            arguments = [str(app_root)]
            for path, expected in paths:
                arguments.extend((str(path), str(int(expected))))
            result = run_fixture(executable, *arguments)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("16 app classification cases, 0 failures", result.stdout)

    def test_public_declaration_names_match_the_implementation(self):
        header = (ROOT / "BaseBin/libjailbreak/src/roothider/common.h").read_text()
        declaration = next(line for line in header.splitlines() if line.startswith("bool isSubPathOf("))
        self.assertIn("bool isSubPathOf(const char* child, const char* parent);", declaration)


if __name__ == "__main__":
    unittest.main()
