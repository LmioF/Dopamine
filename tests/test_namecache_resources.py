import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class NamecacheResourceTests(unittest.TestCase):
    def test_operation_owned_tail_and_bounded_diagnostics(self):
        declarations = (ROOT / "BaseBin/libjailbreak/src/roothider/unsandbox.h").read_text()
        transaction = (ROOT / "BaseBin/libjailbreak/src/roothider/namecache_transaction.h").read_text()
        cases = ["success", "repeated", "dir-open-refused", "file-open-refused", "tail-open-refused",
                 "tail-vnode-refused", "dir-vnode-refused", "file-vnode-refused", "new-open-refused",
                 "getpath-refused", "tail-fd-zero", "child-cycle", "hash-cycle",
                 "writer-lock-refused", "stale-under-lock", "write-refused", "vnode-ref-refused",
                 "counter-publish-refused"]
        failures = []
        for version in (1, 2):
            path = ROOT / f"BaseBin/libjailbreak/src/roothider/unsandbox{version}.m"
            source = "\n".join(line for line in path.read_text().splitlines()
                               if not line.lstrip().startswith(("#include", "#import")))
            implementation = declarations + "\n" + transaction + "\n" + source + f"\n#define UNSANDBOX_IMPL unsandbox{version}\n"
            for enabled in (False, True):
                flags = [f"-DFIXTURE_VERSION={version}", "-Wno-sign-compare", "-Wno-unused-variable"]
                if enabled:
                    flags.append("-DENABLE_LOGS=1")
                with tempfile.TemporaryDirectory(prefix="namecache-resources-") as temporary:
                    executable = compile_fixture(pathlib.Path(temporary), implementation,
                                                 "tests/namecache_resource_tests.c", flags)
                    for case in cases:
                        result = run_fixture(executable, case)
                        if result.returncode or "runtime error:" in result.stderr:
                            failures.append(f"v{version} logs={enabled} {case}: {result.returncode}\n{result.stdout}{result.stderr}")
        self.assertFalse(failures, "\n".join(failures))
        print(f"Namecache resources: {len(cases) * 4} actual-source scenarios passed")


if __name__ == "__main__":
    unittest.main()
