"""Negative checks that an offline database cannot silently be "restored"."""
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import chaos33_db_audit as audit


class OfflineDatabaseAudit(unittest.TestCase):
    def make_db(self, directory: Path) -> Path:
        path = directory / "conductor.sqlite3"
        conn = sqlite3.connect(str(path))
        conn.execute("create table evidence (x text)")
        conn.execute("insert into evidence values ('test-only')")
        conn.commit()
        conn.close()
        return path

    def test_clean_offline_copy_is_not_recovery_certification(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make_db(root)
            manifest = audit.capture(root)
            result = audit.verify(root, manifest)
            self.assertEqual(result["status"], "OFFLINE_SNAPSHOT_INTACT")
            self.assertFalse(result["database_restored"])
            self.assertFalse(result["signed_chain_integrity_proven"])

    def test_corrupted_sqlite_data_is_blocked(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            db = self.make_db(root)
            manifest = audit.capture(root)
            db.write_bytes(b"destroyed sqlite test snapshot")
            report = audit.verify(root, manifest)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertFalse(report["sqlite_integrity"]["conductor.sqlite3"])

    def test_modified_valid_sqlite_still_detected_by_digest(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            db = self.make_db(root)
            manifest = audit.capture(root)
            conn = sqlite3.connect(str(db))
            conn.execute("insert into evidence values ('unauthorized')")
            conn.commit()
            conn.close()
            report = audit.verify(root, manifest)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertTrue(report["sqlite_integrity"]["conductor.sqlite3"])

    def test_missing_file_is_not_a_fresh_database(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            db = self.make_db(root)
            manifest = audit.capture(root)
            db.unlink()
            self.assertEqual(audit.verify(root, manifest)["status"], "BLOCKED")

    def test_symlink_snapshot_is_refused(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make_db(root)
            (root / "unsafe").symlink_to(root / "conductor.sqlite3")
            with self.assertRaises(ValueError):
                audit.capture(root)

    def test_forged_manifest_cannot_claim_valid(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make_db(root)
            manifest = audit.capture(root)
            manifest["schema"] = "wrong"
            self.assertEqual(audit.verify(root, manifest)["status"], "BLOCKED")

    def test_capture_manifest_json_roundtrip(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make_db(root)
            data = json.loads(json.dumps(audit.capture(root)))
            self.assertEqual(audit.verify(root, data)["status"], "OFFLINE_SNAPSHOT_INTACT")


if __name__ == "__main__":
    unittest.main()
