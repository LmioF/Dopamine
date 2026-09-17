import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, function_source, compile_fixture, run_fixture


class RemoteDyldSafetyTests(unittest.TestCase):
    def test_hook_code_restores_execute_permission_over_full_branch(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        entry_start = source.index("int hook_dyld_entry(")
        entry_end = source.index("\nint hook_dyld_function(", entry_start)
        function_start = source.index("int hook_dyld_function(")
        function_end = source.index("\nint proc_patch_dyld_internal", function_start)
        implementation = "\n\n".join([
            source[entry_start:entry_end],
            source[function_start:function_end],
        ])
        with tempfile.TemporaryDirectory(prefix="remote-dyld-range-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation, "tests/remote_dyld_safety_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_metadata_and_loader_failures_are_bounded(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        task_set = function_source("BaseBin/libjailbreak/src/roothider/dyld_patch.m", "task_set_dyld_info_internal")
        load_info = function_source("BaseBin/libjailbreak/src/roothider/dyld_patch.m", "loadDyldInfo")
        proc_start = source.index("int proc_patch_dyld_internal(")
        proc_end = source.index("\nint proc_patch_dyld(", proc_start)
        proc_patch = source[proc_start:proc_end]
        symbol_lookup = function_source("BaseBin/libjailbreak/src/roothider/dyld_patch.m", "get_symbol")

        self.assertNotIn("abort();", task_set)
        self.assertIn("kreadbuf", task_set)
        self.assertIn("kwritebuf", task_set)
        self.assertIn("candidateCount", task_set)
        self.assertIn("!= 0", task_set)

        self.assertIn("if (!csHandle)", symbol_lookup)
        self.assertIn("if (!__CSSymbolicatorCreateWithPathAndArchitecture", symbol_lookup)
        self.assertNotIn("loadDyldCache_function == 0", load_info)
        self.assertIn("loadDyldCache_function == 0", proc_patch)
        self.assertNotIn("assert(", proc_patch)

        failure = source.index("thread_get_state", source.index("int proc_patch_dyld_internal"))
        cleanup = source.index("reentry_end:", failure)
        snippet = source[failure:cleanup]
        self.assertIn("goto reentry_end;", snippet)

    def test_metadata_publication_is_transactional_before_reentry(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        self.assertIn("struct task_dyld_info_snapshot", source)
        self.assertIn("restore_task_dyld_info_snapshot", source)
        self.assertIn("task_set_dyld_info_internal", source)

        proc_start = source.index("int proc_patch_dyld_internal(")
        proc_end = source.index("\nint proc_patch_dyld(", proc_start)
        proc_patch = source[proc_start:proc_end]
        self.assertIn("keepRemoteMapping", proc_patch)
        publication = proc_patch.index("task_set_dyld_info_internal")
        self.assertLess(publication, proc_patch.index("hook_dyld_entry", publication))
        self.assertLess(publication, proc_patch.index("thread_set_state", publication))
        self.assertIn("restore_task_dyld_info_snapshot", proc_patch[publication:])


if __name__ == "__main__":
    unittest.main()
