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

    def test_default_root_and_admin_accounts_and_two_questions(self):
        rows = self.conn.execute(
            "SELECT username, role, can_config, security_question_2 FROM users "
            "WHERE username IN ('root', 'admin') ORDER BY username"
        ).fetchall()
        self.assertEqual([(r["username"], r["role"]) for r in rows],
                         [("admin", "admin"), ("root", "root")])
        self.assertTrue(all(r["can_config"] for r in rows))
        self.assertTrue(all(r["security_question_2"] == "" for r in rows))

    def test_archived_logs_are_separate_and_included_in_backup(self):
        self.conn.execute(
            "INSERT INTO loan_logs (occurred_at, barcode, title, class_name, user_name, action) "
            "VALUES ('2025/09/01 10:00:00', 'B1', '書', 'A班', '小明', '借書')"
        )
        row_id = self.conn.execute("SELECT id FROM loan_logs").fetchone()[0]
        self.conn.execute(
            "INSERT INTO loan_logs_archive (id, occurred_at, created_at, barcode, title, class_name, user_name, action) "
            "VALUES (?, '2024/09/01 10:00:00', '2024/09/01 10:00:00', 'B0', '舊書', 'A班', '小華', '還書')",
            (row_id + 1000,)
        )
        self.conn.commit()
        payload = server.build_backup(self.conn)["data"]["loanLogs"]
        self.assertEqual(len(payload), 2)
        self.assertTrue(any(item["archived"] for item in payload))


if __name__ == "__main__":
    unittest.main()
