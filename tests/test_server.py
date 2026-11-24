import os
import tempfile
import unittest

import server


class ServerDataTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "library.db")
        server.init_db(self.db_path)
        self.conn = server.connect(self.db_path)

    def tearDown(self):
        self.conn.close()
        for path in (self.db_path, self.db_path + "-wal", self.db_path + "-shm"):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        self.tmpdir.cleanup()

    def test_backup_contains_operational_data_without_password(self):
        payload = server.build_backup(self.conn)["data"]
        self.assertIn("reservations", payload)
        self.assertIn("accounts", payload)
        self.assertIn("settings", payload)
        self.assertNotIn("admin_password", payload["settings"])
        self.assertNotIn("password", payload["accounts"][0] if payload["accounts"] else {})

    def test_old_backup_shape_still_imports(self):
        classes, members, books, logs, categories, reservations, accounts, settings = server.validate_import({
            "libConfig": {"classes": ["測試班"]},
            "memberDB": {"測試班": ["小明"]},
            "bookDB": {"B001": {"title": "測試書"}},
            "loanLogs": [],
        })
        self.assertEqual(classes, ["測試班"])
        self.assertEqual(members["測試班"], ["小明"])
        self.assertEqual(books["B001"]["status"], "在館")
        self.assertEqual(categories, [])
        self.assertEqual(reservations, [])
        self.assertEqual(accounts, [])
        self.assertEqual(settings, {})

    def test_static_allowlist_excludes_sensitive_project_files(self):
        handler = server.Handler.__new__(server.Handler)
        self.assertIsNotNone(handler._resolve_static("/index.html"))
        self.assertIsNotNone(handler._resolve_static("/vendor/qrcode.min.js"))
        for path in ("/server.py", "/update.sh", "/qr.py", "/docs/操作手冊.md", "/data/library.db"):
            self.assertIsNone(handler._resolve_static(path), path)

    def test_settings_survive_database_reinitialization(self):
        self.conn.execute("UPDATE settings SET value = 'custom' WHERE key = 'backup_time'")
        self.conn.close()
        server.init_db(self.db_path)
        conn = server.connect(self.db_path)
        try:
            self.assertEqual(conn.execute(
                "SELECT value FROM settings WHERE key = 'backup_time'"
            ).fetchone()[0], "custom")
        finally:
            conn.close()
            self.conn = server.connect(self.db_path)


if __name__ == "__main__":
    unittest.main()
