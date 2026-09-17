import pathlib
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]


def function_source(path: str, name: str) -> str:
    source = (ROOT / path).read_text()
    match = re.search(r"^[^\n;]*\b" + re.escape(name) + r"\([^;]*?\n\{.*?^\}", source, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"Could not extract {name} from {path}")
    return match.group(0)


def compile_fixture(directory: pathlib.Path, implementation: str, harness: str, extra_flags=()) -> pathlib.Path:
    (directory / "implementation.h").write_text(implementation)
    executable = directory / "fixture"
    result = subprocess.run(
        ["xcrun", "--sdk", "macosx", "clang", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-parameter", "-Wno-unused-function", "-fsanitize=address,undefined",
         "-fno-sanitize-recover=all",
         "-g", "-I", str(directory), *extra_flags, str(ROOT / harness), "-o", str(executable)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return executable


def run_fixture(executable: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(executable), *arguments], capture_output=True, text=True, timeout=30)
