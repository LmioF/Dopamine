import pathlib
import re
import os
import subprocess
import tempfile
import time
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


DEBUGSERVER = pathlib.Path(
    "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver"
)


class EntitlementBlobDebuggerTests(unittest.TestCase):
    def test_real_debugserver_entitlement_uses_direct_memory_path(self):
        if not DEBUGSERVER.exists():
            self.skipTest("Xcode debugserver is unavailable")

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

        implementation = "\n\n".join((
            function_source("BaseBin/systemhook/src/main.c", "copy_entitlements_xpc"),
            function_source("BaseBin/systemhook/src/main.c", "process_requires_hookd"),
        ))

        waiter = f"port_review_debugger_entitlement_{os.getpid()}"
        debugserver = subprocess.Popen(
            [str(DEBUGSERVER), "127.0.0.1:0", "--waitfor=" + waiter],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.2)
            status = debugserver.poll()
            if status is not None:
                stderr = debugserver.stderr.read() if debugserver.stderr else ""
                self.fail(f"debugserver exited early with {status}: {stderr}")
            with tempfile.TemporaryDirectory(prefix="entitlement-debugserver-host-") as temporary:
                directory = pathlib.Path(temporary)
                (directory / "declarations.h").write_text("\n".join(declarations))
                executable = compile_fixture(
                    directory, implementation, "tests/entitlement_blob_debugger_tests.c", ("-fblocks",),
                )
                result = run_fixture(executable, str(debugserver.pid))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertIn("debugger entitlement parsing passed", result.stdout)
        finally:
            if debugserver.poll() is None:
                debugserver.terminate()
                try:
                    debugserver.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    debugserver.kill()
                    debugserver.wait(timeout=5)
            if debugserver.stderr:
                debugserver.stderr.close()


if __name__ == "__main__":
    unittest.main()
