import pathlib
import subprocess
import tempfile
import unittest

from port_review_test_support import ROOT


class AuxiliaryRequestScopeTests(unittest.TestCase):
    def test_request_identity_and_object_tags_are_scoped(self):
        helper = ROOT / "BaseBin/roothidehooks/request_scope.m"
        self.assertTrue(helper.exists(), "request-scope helper is required for reusable object tags")

        cfprefs = (ROOT / "BaseBin/roothidehooks/cfprefsd.x").read_text()
        springboard = (ROOT / "BaseBin/roothidehooks/springboard.x").read_text()
        lsd = (ROOT / "BaseBin/roothidehooks/lsd.x").read_text()

        self.assertIn("RHPidScope clientScope = rhPidScopeBegin(&gCurrentClientPid, clientPid);", cfprefs)
        self.assertIn("rhPidScopeEnd(&gCurrentClientPid, clientScope);", cfprefs)
        self.assertIn("@try", cfprefs)
        self.assertIn("@finally", cfprefs)
        self.assertNotIn("@available(iOS 17.0", cfprefs)
        self.assertIn("id self, SEL selector, xpc_object_t message", cfprefs)

        self.assertIn("rhAssociatedFlagScopeBegin", springboard)
        self.assertIn("rhAssociatedFlagScopeEnd", springboard)
        self.assertIn("rhAssociatedFlagScopeBegin", lsd)
        self.assertIn("rhAssociatedFlagScopeEnd", lsd)
        self.assertNotIn("objc_setAssociatedObject(url, kBlockSchemeTagKey, @YES", lsd)
        self.assertNotIn("objc_setAssociatedObject(bundleIdentifier, kDenyQueryTagKey, @YES", springboard)

        self.assertIn("BOOL previousHide = g_utrHide;", lsd)
        self.assertIn("g_utrHide = utrHideClientBlacklisted(self);", lsd)
        self.assertIn("g_utrHide = previousHide;", lsd)
        self.assertIn("getResourceValuesForKeys:(id)keys mimic:(id)mimic preferredLocalizations:(id)locs", lsd)
        self.assertNotIn("assert(ret == NO)", lsd)
        self.assertNotIn("assert(success == NO)", lsd)

        with tempfile.TemporaryDirectory(prefix="aux-request-scope-") as temporary:
            executable = pathlib.Path(temporary) / "fixture"
            sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            clang = subprocess.check_output(["xcrun", "--sdk", "macosx", "--find", "clang"], text=True).strip()
            result = subprocess.run(
                [clang, "-isysroot", sdk, "-fobjc-arc", "-framework", "Foundation",
                 "-I", str(ROOT / "BaseBin/roothidehooks"),
                 str(ROOT / "tests/auxiliary_request_scopes_tests.m"), str(helper),
                 "-o", str(executable)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
