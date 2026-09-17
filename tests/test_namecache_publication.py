import pathlib
import unittest

from port_review_test_support import ROOT


class NamecachePublicationTests(unittest.TestCase):
    def test_patchfinder_exports_namecache_writer_contract(self):
        info = (ROOT / "BaseBin/libjailbreak/src/info.h").read_text()
        patchfinder = (ROOT / "Application/Dopamine/Jailbreak/DORoothidePatchfinder.c").read_text()

        for field in ("namecache_rw_lock", "lck_rw_lock_exclusive", "lck_rw_done",
                      "vnode_ref_ext", "vnode_rele_ext"):
            self.assertIn(f"kernelSymbol.{field}", info)
            self.assertIn(f'"kernelSymbol.{field}"', patchfinder)

        self.assertIn("Taking non-sleepable RW lock with preemption enabled", patchfinder)
        self.assertIn("Releasing non-exclusive RW lock without a reader refcount", patchfinder)
        self.assertIn("vnode_ref_ext: vp %p has no valid reference", patchfinder)
        self.assertIn("vnode_rele_ext: vp %p usecount -ve", patchfinder)

    def test_both_publishers_use_writer_lock_and_modern_sequence_counter(self):
        for version in (1, 2):
            source = (ROOT / f"BaseBin/libjailbreak/src/roothider/unsandbox{version}.m").read_text()
            lock = source.index("rh_namecache_writer_lock")
            first_write = min(index for token in ("rh_namecache_write32(", "rh_namecache_write64(")
                              if (index := source.find(token, lock)) >= 0)
            unlock = source.index("rh_namecache_writer_unlock", first_write)
            self.assertLess(lock, first_write)
            self.assertLess(first_write, unlock)

        modern = (ROOT / "BaseBin/libjailbreak/src/roothider/unsandbox2.m").read_text()
        self.assertIn("rh_namecache_counter_invalidate", modern)
        self.assertIn("rh_namecache_counter_publish", modern)
        for version in (1, 2):
            source = (ROOT / f"BaseBin/libjailbreak/src/roothider/unsandbox{version}.m").read_text()
            self.assertNotIn("v_usecount+1", source)
            self.assertIn("rh_namecache_retain_vnode", source)


if __name__ == "__main__":
    unittest.main()
