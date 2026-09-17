import pathlib
import plistlib
import re
import shutil
import subprocess
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class EntitlementBlobHostTests(unittest.TestCase):
    def test_real_signed_self_process_and_xpc_parser(self):
        blob = (ROOT / "BaseBin/ChOma/src/CSBlob.h").read_text()
        codesign = (ROOT / "BaseBin/libjailbreak/src/codesign.h").read_text()
        xpc = (ROOT / "BaseBin/_external/include/xpc_private.h").read_text()
        patterns = (
            (blob, r"typedef struct __GenericBlob \{.*?\} CS_GenericBlob;"),
            (blob, r"CSMAGIC_EMBEDDED_ENTITLEMENTS\s*=\s*0x[0-9a-fA-F]+"),
            (codesign, r"^#define CS_OPS_ENTITLEMENTS_BLOB[^\n]+"),
            (codesign, r"^int csops\([^\n]+"),
            (xpc, r"^extern XPC_RETURNS_RETAINED xpc_object_t xpc_create_from_plist[^\n]+"),
        )
        declarations = []
        for source, pattern in patterns:
            match = re.search(pattern, source, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, pattern)
            declarations.append(match.group(0))
        declarations[1] = "enum { " + declarations[1] + " };"
        implementation = function_source("BaseBin/systemhook/src/main.c", "copy_entitlements_xpc")
        with tempfile.TemporaryDirectory(prefix="entitlement-self-host-") as temporary:
            directory = pathlib.Path(temporary)
            (directory / "declarations.h").write_text("\n".join(declarations))
            executable = compile_fixture(
                directory, implementation, "tests/entitlement_blob_host_tests.c", ("-fblocks",),
            )
            for mode in ("none", "empty"):
                with self.subTest(mode=mode):
                    signed = directory / ("signed-" + mode)
                    shutil.copy2(executable, signed)
                    command = ["codesign", "--force", "--sign", "-", "--timestamp=none",
                               "--identifier", "org.portreview.entitlements." + mode]
                    if mode != "none":
                        plist = directory / (mode + ".plist")
                        plist.write_bytes(plistlib.dumps({}))
                        command.extend(("--entitlements", str(plist)))
                    command.append(str(signed))
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    verified = subprocess.run(
                        ["codesign", "--verify", "--strict", str(signed)],
                        capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
                    result = run_fixture(signed, mode)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertIn("real self-process entitlement parsing passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
