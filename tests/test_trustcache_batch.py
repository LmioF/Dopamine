import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class TrustcacheBatchTests(unittest.TestCase):
    def test_cursor_capacity_and_io_failures(self):
        structures = (ROOT / "BaseBin/libjailbreak/src/trustcache_structs.h").read_text()
        structures = "\n".join(line for line in structures.splitlines() if not line.startswith("#include"))
        path = "BaseBin/libjailbreak/src/trustcache.c"
        implementation = structures + "\n"
        implementation += "\n".join(function_source(path, name) for name in
                                     ("_trustcache_file_sort_entry_comparator_v1", "_trustcache_file_sort", "jb_trustcache_add_entries"))
        with tempfile.TemporaryDirectory(prefix="port-trustcache-batch-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation,
                                         "tests/trustcache_batch_tests.c", ["-fblocks"])
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("14 trustcache batch cases, 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
