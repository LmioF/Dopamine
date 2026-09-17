import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class XPFTeardownTests(unittest.TestCase):
    def test_all_owned_resources_partial_initialization_and_repeated_stop(self):
        header = (ROOT / "BaseBin/XPF/src/xpf.h").read_text()
        source = (ROOT / "BaseBin/XPF/src/xpf.c").read_text()
        item = re.search(r"typedef struct s_XPFItem \{.*?\} XPFItem;", header, re.DOTALL).group(0)
        state = re.search(r"typedef struct s_XPF \{.*?\} XPF;", header, re.DOTALL).group(0)
        global_state = re.search(r"^XPF gXPF = .*?;", source, re.MULTILINE).group(0)
        implementation = "\n".join((item, state, global_state,
                                     function_source("BaseBin/XPF/src/xpf.c", "xpf_stop")))
        sections = re.findall(r"PFSection \*(kernel\w+);", state)
        initialize_sections = "\n".join(
            f"if (selected < 0 || selected == {index}) gXPF.{field} = resource(SECTION, gXPF.kernelContainer);"
            for index, field in enumerate(sections)
        )
        strings = ("kernelVersionString", "kernelInfoPlist", "darwinVersion", "xnuBuild", "xnuPlatform", "osVersion")
        initialize_strings = "\n".join(f"gXPF.{field} = (char *)resource(BUFFER, NULL);" for field in strings)
        implementation += ("\nstatic void initialize_kernel(int selected)\n{\n"
                           "gXPF.kernelFd = 42; gXPF.kernelSize = 4096;\n"
                           "gXPF.mappedKernel = resource(MAPPING, NULL);\n"
                           "gXPF.decompressedKernel = resource(BUFFER, NULL);\n"
                           "gXPF.kernelContainer = resource(CONTAINER, gXPF.decompressedKernel);\n"
                           "gXPF.kernel = (MachO *)gXPF.kernelContainer;\n" + initialize_sections + "\n" +
                           initialize_strings + "\n}\n")
        implementation += f"\n#define KERNEL_SECTION_COUNT {len(sections)}\n"
        with tempfile.TemporaryDirectory(prefix="port-xpf-teardown-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation, "tests/xpf_teardown_tests.c", ("-fno-sanitize-recover=all",))
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("XPF teardown: 0 failures", result.stdout)


if __name__ == "__main__":
    unittest.main()
