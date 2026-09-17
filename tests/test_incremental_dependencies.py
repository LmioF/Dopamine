import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = (
    ("BaseBin/systemhook", "systemhook.dylib", False),
    ("BaseBin/launchdhook", "launchdhook.dylib", True),
    ("BaseBin/jailbreakd", "jailbreakd", True),
    ("Packages/libkrw-provider", "libkrw-dopamine.dylib", True),
)


class IncrementalDependenciesTests(unittest.TestCase):
    def check_dependency(self, relative, target, dependency):
        with tempfile.TemporaryDirectory(prefix="port-build-graph-") as directory:
            root = pathlib.Path(directory)
            component = root / relative
            component.mkdir(parents=True)
            shutil.copyfile(ROOT / relative / "Makefile", component / "Makefile")
            files = [
                component / "src/fixture.c",
                component / "src/fixture.h",
                root / "BaseBin/.include/libjailbreak/info.h",
                root / "BaseBin/.build/libjailbreak.dylib",
                root / "BaseBin/.build/libchoma.dylib",
                root / "BaseBin/_external/lib/libMobileGestalt.tbd",
                root / "BaseBin/libjailbreak/src/jbclient_fixture.c",
                root / "BaseBin/libjailbreak/src/fixture.h",
                root / "BaseBin/systemhook/src/common/fixture.h",
                root / "BaseBin/_external/modules/litehook/src/fixture.h",
            ]
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n")
                os.utime(path, (100, 100))
            os.utime(component / "Makefile", (100, 100))
            output = component / target
            output.write_text("timestamp-only fixture; never executed\n")
            os.utime(output, (200, 200))
            command = [shutil.which("gmake") or "make", "-q", target]
            current = subprocess.run(command, cwd=component, capture_output=True, text=True)
            self.assertEqual(current.returncode, 0, current.stderr)
            changed = component / dependency if not dependency.startswith("/") else root / dependency[1:]
            os.utime(changed, (300, 300))
            stale = subprocess.run(command, cwd=component, capture_output=True, text=True)
            self.assertEqual(stale.returncode, 1, f"{relative}: {dependency} did not invalidate {target}: {stale.stderr}")

    def test_staged_header_invalidates_all_consumers(self):
        for relative, target, _ in TARGETS:
            with self.subTest(target=target):
                self.check_dependency(relative, target, "/BaseBin/.include/libjailbreak/info.h")

    def test_local_header_invalidates_all_consumers(self):
        for relative, target, _ in TARGETS:
            with self.subTest(target=target):
                self.check_dependency(relative, target, "src/fixture.h")

    def test_linked_library_invalidates_its_consumers(self):
        for relative, target, links_jailbreak in TARGETS:
            if links_jailbreak:
                with self.subTest(target=target):
                    self.check_dependency(relative, target, "/BaseBin/.build/libjailbreak.dylib")

    def test_compiled_shared_sources_keep_their_private_headers(self):
        self.check_dependency("BaseBin/systemhook", "systemhook.dylib", "/BaseBin/libjailbreak/src/fixture.h")
        self.check_dependency("BaseBin/launchdhook", "launchdhook.dylib", "/BaseBin/systemhook/src/common/fixture.h")

    def test_makefile_changes_invalidate_all_consumers(self):
        for relative, target, _ in TARGETS:
            with self.subTest(target=target):
                self.check_dependency(relative, target, "Makefile")

    def test_source_changes_invalidate_all_consumers(self):
        for relative, target, _ in TARGETS:
            with self.subTest(target=target):
                self.check_dependency(relative, target, "src/fixture.c")


if __name__ == "__main__":
    unittest.main()
