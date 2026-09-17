import pathlib
import shutil
import subprocess
import tempfile
import unittest

from port_review_test_support import ROOT


class RecursiveTrustFailureTests(unittest.TestCase):
    def test_recursive_trust_preserves_failure_identity(self):
        build_root = ROOT / ".build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="recursive-trust-", dir=build_root) as temporary:
            directory = pathlib.Path(temporary)
            sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            ios_sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
            clang = subprocess.check_output(["xcrun", "--sdk", "macosx", "--find", "clang"], text=True).strip()

            harness = directory / "recursive_trust_tests"
            compile_result = subprocess.run(
                [
                    clang,
                    "-isysroot", sdk,
                    "-fobjc-arc", "-fblocks",
                    "-Wno-deprecated-declarations",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    "-I", str(ROOT / "BaseBin/ChOma/include"),
                    "-idirafter", str(ROOT / "BaseBin/_external/include"),
                    "-L", str(ROOT / "BaseBin/XPF/output/macos"),
                    "-lxpf", "-framework", "Foundation",
                    str(ROOT / "tests/recursive_trust_tests.m"),
                    str(ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m"),
                    "-o", str(harness),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stdout + compile_result.stderr)

            source = directory / "dep.c"
            source.write_text("int dependency_value(void) { return 7; }\n")
            main = directory / "main.c"
            main.write_text("extern int dependency_value(void); int main(void) { return dependency_value() == 7 ? 0 : 1; }\n")

            required_lib = directory / "librequired.dylib"
            weak_lib = directory / "libweak.dylib"
            required_exe = directory / "required"
            weak_exe = directory / "weak"
            plain_exe = directory / "plain"
            replacement = directory / "replacement"

            commands = [
                [clang, "-isysroot", sdk, "-dynamiclib", str(source), "-install_name", "@rpath/librequired.dylib", "-o", str(required_lib)],
                [clang, "-isysroot", sdk, "-dynamiclib", str(source), "-install_name", "@rpath/libweak.dylib", "-o", str(weak_lib)],
                [clang, "-isysroot", sdk, str(main), str(required_lib), "-Wl,-rpath,@loader_path", "-o", str(required_exe)],
                [clang, "-isysroot", sdk, str(main), "-Wl,-weak_library," + str(weak_lib), "-Wl,-rpath,@loader_path", "-o", str(weak_exe)],
                [clang, "-isysroot", sdk, "-x", "c", "-", "-o", str(plain_exe)],
                [clang, "-isysroot", sdk, "-x", "c", "-", "-o", str(replacement)],
            ]
            for index, command in enumerate(commands):
                input_text = "int main(void) { return 0; }\n" if index >= 4 else None
                result = subprocess.run(command, input=input_text, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            for binary in (required_exe, weak_exe, plain_exe, replacement):
                result = subprocess.run(["codesign", "-s", "-", "--force", str(binary)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            required_lib.unlink()
            weak_lib.unlink()

            env = dict(**__import__("os").environ)
            env["DYLD_LIBRARY_PATH"] = str(ROOT / "BaseBin/XPF/output/macos")
            cases = [
                ("required-missing", required_exe, None, 1),
                ("weak-missing", weak_exe, None, 0),
                ("branding-failure", plain_exe, None, 1),
                ("already-trusted", plain_exe, None, 0),
                ("replacement", plain_exe, replacement, 1),
                ("normalization-failure", plain_exe, None, 1),
            ]
            failures = []
            for case, executable, replacement_path, expect_failure in cases:
                arguments = [str(harness), case, str(executable)]
                if replacement_path:
                    replacement_copy = directory / "replacement-copy"
                    shutil.copy2(replacement_path, replacement_copy)
                    arguments.append(str(replacement_copy))
                result = subprocess.run(arguments, env=env, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    failures.append(f"{case}: exit {result.returncode}\n{result.stdout}{result.stderr}")
            self.assertFalse(failures, "\n".join(failures))

            arm64_dir = directory / "arm64"
            arm64e_dir = directory / "arm64e"
            arm64_dir.mkdir()
            arm64e_dir.mkdir()
            leaf_source = directory / "archleaf.c"
            leaf_source.write_text("int leaf_value(void) { return 7; }\n")
            dep_source = directory / "archdep.c"
            dep_source.write_text("extern int leaf_value(void); int dependency_value(void) { return leaf_value(); }\n")
            arch_main_source = directory / "archmain.c"
            arch_main_source.write_text("extern int dependency_value(void); int main(void) { return dependency_value(); }\n")
            main_slices = []
            dep_slices = []
            for arch, target_dir in (("arm64", arm64_dir), ("arm64e", arm64e_dir)):
                leaf = target_dir / "libleaf.dylib"
                dep_slice = directory / f"libdep-{arch}.dylib"
                main_slice = directory / f"main-{arch}"
                for command in (
                    [clang, "-isysroot", ios_sdk, "-arch", arch, "-miphoneos-version-min=15.0", "-dynamiclib", str(leaf_source),
                     "-install_name", "@rpath/libleaf.dylib", "-o", str(leaf)],
                    [clang, "-isysroot", ios_sdk, "-arch", arch, "-miphoneos-version-min=15.0", "-dynamiclib", str(dep_source), str(leaf),
                     "-install_name", "@rpath/libdep.dylib", f"-Wl,-rpath,@loader_path/{arch}", "-o", str(dep_slice)],
                    [clang, "-isysroot", ios_sdk, "-arch", arch, "-miphoneos-version-min=15.0", str(arch_main_source), str(dep_slice),
                     "-Wl,-rpath,@loader_path", "-o", str(main_slice)],
                ):
                    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for binary in (leaf, main_slice):
                    result = subprocess.run(["codesign", "-s", "-", "--force", str(binary)], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if arch == "arm64e":
                    data = bytearray(dep_slice.read_bytes())
                    data[8:12] = (2).to_bytes(4, "little")
                    dep_slice.write_bytes(data)
                result = subprocess.run(["codesign", "-s", "-", "--force", str(dep_slice)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                dep_slices.append(dep_slice)
                main_slices.append(main_slice)

            fat_dep = directory / "libdep.dylib"
            result = subprocess.run(["lipo", "-create", *(str(item) for item in dep_slices), "-output", str(fat_dep)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(["codesign", "-s", "-", "--force", str(fat_dep)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            fat_main = directory / "fat-main"
            result = subprocess.run(["lipo", "-create", *(str(item) for item in main_slices), "-output", str(fat_main)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(["codesign", "-s", "-", "--force", str(fat_main)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            arch_failures = []
            for scenario in ("arch-arm64", "arch-arm64e", "arch-arm64e-generic"):
                result = subprocess.run([str(harness), scenario, str(fat_main)], env=env,
                                        capture_output=True, text=True, timeout=30)
                if result.returncode:
                    arch_failures.append(f"{scenario}: exit {result.returncode}\n{result.stdout}{result.stderr}")
            self.assertFalse(arch_failures, "\n".join(arch_failures))


if __name__ == "__main__":
    unittest.main()
