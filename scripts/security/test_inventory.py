"""Offline tests for Sprint 16 inventory logic."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory


class InventoryTests(unittest.TestCase):
    def test_locked_dependencies_are_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            lock = Path(d) / "Cargo.lock"
            lock.write_text(
                'version = 4\n[[package]]\nname = "sample"\nversion = "1.2.3"\n'
                'source = "registry+https://example.org"\nchecksum = "f00"\n'
            )
            data = inventory.lock_inventory(lock)
            self.assertEqual(data["package_count"], 1)
            self.assertEqual(data["packages"][0]["name"], "sample")
            self.assertEqual(data["packages"][0]["version"], "1.2.3")

    def test_real_unsafe_and_comments_are_distinguished(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "example.rs"
            path.write_text(
                "// unsafe { just a comment }\n"
                "pub unsafe fn suspicious() {}\n"
                "unsafe { a(); }\n"
                "let harmless = true;\n"
            )
            lines = inventory.unsafe_source_inventory(path)
            self.assertEqual([x["line"] for x in lines], [2, 3])

    def test_inventory_marks_external_advisory_scan_missing(self):
        self.assertTrue(inventory.UNSAFE_DECLARATION.search("unsafe extern \"C\" {}"))
        self.assertFalse(inventory.UNSAFE_DECLARATION.search("#![forbid(unsafe_code)]"))


if __name__ == "__main__":
    unittest.main()
