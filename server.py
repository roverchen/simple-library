#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
幼兒園圖書資訊管理系統 — 後端伺服器

只用 Python 標準函式庫：HTTP 伺服器 + SQLite，沒有 npm / pip 相依套件，
可完全離線執行。

啟動：
    python3 server.py                 # http://localhost:8000
    python3 server.py --port 8080
    python3 server.py --host 127.0.0.1
    python3 server.py --https --cert cert.pem --key key.pem

資料庫預設位於 data/library.db，可用 --db 指定其他位置。
"""

import argparse
import csv
import hashlib
import hmac
import io
import json
import math
import os
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from pdf_report import build_table_pdf

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(BASE_DIR, "data", "library.db")

APP_ID = "幼兒園圖書資訊管理系統"
BACKUP_VERSION = 2
BACKUP_DIR = os.path.join(BASE_DIR, "data", "backups")
BACKUP_RETENTION = 7
DEFAULT_CLASSES = ["太陽班", "月亮班", "星星班", "彩虹班", "白雲班", "小草班"]
DEFAULT_PASSWORD = "1234"

SESSION_TTL = 12 * 60 * 60          # 12 小時
PBKDF2_ITERATIONS = 200_000
MAX_BODY = 64 * 1024 * 1024         # 匯入備份上限 64 MB
MAX_JSON = 2 * 1024 * 1024          # 其他 API 上限 2 MB
MAX_BOOKS = 100_000
MAX_LOGS = 500_000
MAX_MEMBERS_PER_CLASS = 2_000

# 靜態檔案不允許存取的目錄／檔案
DENY_PREFIXES = ("data",)
DENY_FILES = {"server.py", "schema.sql", "pdf_report.py"}

_lock = threading.Lock()
_login_attempts = {}                # ip -> [count, window_start]


class ApiError(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra


# --------------------------------------------------------------------------
# 資料庫
# --------------------------------------------------------------------------

DB_PATH = DEFAULT_DB


def connect(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS, salt.hex(), digest.hex()
    )


def verify_password(password, stored):
    try:
        algo, iterations, salt, expected = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


def get_setting(conn, key, default):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None or row["value"] is None:
        return default
    try:
        return str(row["value"])
    except Exception:
        return default


def init_db(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    schema_path = os.path.join(BASE_DIR, "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = f.read()

    conn = connect(db_path)
    try:
        conn.executescript(schema)
        conn.execute("PRAGMA user_version = 1")

        try:
            conn.execute("ALTER TABLE books ADD COLUMN due_at TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN user_id INTEGER")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE books ADD COLUMN remarks TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE books ADD COLUMN call_no TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        row = conn.execute(
            "SELECT value FROM settings WHERE key = 'admin_password'"
        ).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("admin_password", hash_password(DEFAULT_PASSWORD)),
            )

        for key, val in (
            ("loan_limit_student", "3"),
            ("loan_limit_teacher", "90"),
            ("loan_days_student", "7"),
            ("loan_days_teacher", "180"),
        ):
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, val),
            )

        count = conn.execute("SELECT COUNT(*) FROM classes").fetchone()[0]
        if count == 0:
            for i, name in enumerate(DEFAULT_CLASSES):
                conn.execute(
                    "INSERT INTO classes (name, sort_order, active) VALUES (?, ?, 1)",
                    (name, i),
                )
    finally:
        conn.close()


def now_display():
    return datetime.now().strftime("%Y/%m/%d %H:%M:%S")


def safe_rollback(conn):
    """交易可能已提交或從未開始，ROLLBACK 失敗時不應掩蓋原始錯誤。"""
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass


def book_json(row):
    return {
        "title": row["title"],
        "assetId": row["asset_id"],
        "status": "報廢" if row["status"] == "報廢" else (
            "借出" if row["loaned_to"] else "在館"
        ),
        "loanedTo": row["loaned_to"],
        "loanClass": row["loan_class"],
        "dueAt": row["due_at"],
        "count": row["borrow_count"],
        "remarks": row["remarks"],
        "callNo": row["call_no"] or "",
    }


def log_json(row):
    return {
        "id": row["id"],
        "date": row["occurred_at"],
        "barcode": row["barcode"],
        "title": row["title"],
        "assetId": row["asset_id"],
        "className": row["class_name"],
        "userName": row["user_name"],
        "action": row["action"],
    }


def build_state(conn):
    classes = [
        r["name"]
        for r in conn.execute(
            "SELECT name FROM classes WHERE active = 1 ORDER BY sort_order, id"
        )
    ]

    # 成員名單包含「已停用班級」的成員，避免調整班級清單時資料消失。
    member_db = {}
    for r in conn.execute(
        "SELECT c.name AS cls, m.name AS member "
        "FROM members m JOIN classes c ON c.id = m.class_id "
        "ORDER BY c.sort_order, c.id, m.id"
    ):
        member_db.setdefault(r["cls"], []).append(r["member"])
    for r in conn.execute("SELECT name FROM classes ORDER BY sort_order, id"):
        member_db.setdefault(r["name"], [])

    books = {}
    for r in conn.execute("SELECT * FROM books ORDER BY rowid"):
        books[r["barcode"]] = book_json(r)

    log_count = conn.execute("SELECT COUNT(*) FROM loan_logs").fetchone()[0]
    return {
        "libConfig": {"classes": classes},
        "memberDB": member_db,
        "bookDB": books,
        "logCount": log_count,
    }


def build_backup(conn):
    state = build_state(conn)
    logs = [
        log_json(r)
        for r in conn.execute("SELECT * FROM loan_logs ORDER BY id DESC")
    ]
    return {
        "app": APP_ID,
        "version": BACKUP_VERSION,
        "exportedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "data": {
            "libConfig": state["libConfig"],
            "memberDB": state["memberDB"],
            "bookDB": state["bookDB"],
            "loanLogs": [
                {
                    "date": log["date"],
                    "barcode": log["barcode"],
                    "className": log["className"],
                    "userName": log["userName"],
                    "title": log["title"],
                    "assetId": log["assetId"],
                    "action": log["action"],
                }
                for log in logs
            ],
        },
    }


def run_auto_backup():
    conn = connect()
    try:
        payload = build_backup(conn)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        filename = "backup-{}.json".format(datetime.now().strftime("%Y%m%d-%H%M%S"))
        path = os.path.join(BACKUP_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        files = sorted(
            f for f in os.listdir(BACKUP_DIR) if f.startswith("backup-") and f.endswith(".json")
        )
        for old in files[:-BACKUP_RETENTION]:
            try:
                os.remove(os.path.join(BACKUP_DIR, old))
            except OSError:
                pass
        return filename
    finally:
        conn.close()


def auto_backup_worker():
    while True:
        time.sleep(86400)
        try:
            run_auto_backup()
        except Exception:
            pass


# --------------------------------------------------------------------------
# 匯入驗證
# --------------------------------------------------------------------------

def _clean_text(value, field, max_len=200, required=False):
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ApiError(400, "{} 格式錯誤".format(field))
    value = value.strip()
    if required and not value:
        raise ApiError(400, "{} 不可空白".format(field))
    if len(value) > max_len:
        raise ApiError(400, "{} 過長（上限 {} 字）".format(field, max_len))
    return value


def validate_import(payload):
    if not isinstance(payload, dict):
        raise ApiError(400, "備份資料格式錯誤")

    lib = payload.get("libConfig") or {}
    if not isinstance(lib, dict):
        lib = {}
    raw_classes = lib.get("classes")
    if not isinstance(raw_classes, list):
        raw_classes = DEFAULT_CLASSES

    classes = []
    for item in raw_classes:
        name = _clean_text(item, "班級名稱", 50)
        if name and name not in classes:
            classes.append(name)
    if not classes:
        classes = list(DEFAULT_CLASSES)
    if len(classes) > 100:
        raise ApiError(400, "班級數量過多")

    raw_members = payload.get("memberDB") or {}
    if not isinstance(raw_members, dict):
        raise ApiError(400, "memberDB 格式錯誤")
    member_db = {}
    for cls, names in raw_members.items():
        cls_name = _clean_text(cls, "班級名稱", 50, required=True)
        if not isinstance(names, list):
            raise ApiError(400, "成員名單格式錯誤")
        if len(names) > MAX_MEMBERS_PER_CLASS:
            raise ApiError(400, "班級成員過多：{}".format(cls_name))
        cleaned = []
        for name in names:
            n = _clean_text(name, "成員姓名", 50, required=True)
            if n not in cleaned:
                cleaned.append(n)
        member_db[cls_name] = cleaned
        # 不在班級清單中的成員班級，匯入時會以「停用」保留，不自動變成啟用。

    raw_books = payload.get("bookDB") or {}
    if not isinstance(raw_books, dict):
        raise ApiError(400, "bookDB 格式錯誤")
    if len(raw_books) > MAX_BOOKS:
        raise ApiError(400, "館藏數量過多")
    books = {}
    for barcode, book in raw_books.items():
        code = _clean_text(barcode, "條碼", 128, required=True)
        if not isinstance(book, dict):
            raise ApiError(400, "館藏資料格式錯誤：{}".format(code))
        title = _clean_text(book.get("title"), "書名", 200, required=True)
        asset = _clean_text(book.get("assetId", ""), "財產編號", 64)
        raw_status = book.get("status") or "在館"
        if not isinstance(raw_status, str):
            raw_status = "在館"
        loaned_to = book.get("loanedTo")
        if loaned_to is not None:
            loaned_to = _clean_text(loaned_to, "借閱人", 50)

        if raw_status == "報廢":
            status = "報廢"
            loaned_to = None
        else:
            # 相容舊資料：status 可能是「借出(王小明)」
            if raw_status.startswith("借出") and not loaned_to:
                loaned_to = raw_status[2:].strip("() ") or None
            if loaned_to:
                status = "借出"
            else:
                status = "在館"
                loaned_to = None
        books[code] = {
            "title": title,
            "asset_id": asset,
            "status": status,
            "loaned_to": loaned_to,
            "count": int(book.get("count") or 0),
        }

    raw_logs = payload.get("loanLogs") or []
    if not isinstance(raw_logs, list):
        raise ApiError(400, "loanLogs 格式錯誤")
    if len(raw_logs) > MAX_LOGS:
        raise ApiError(400, "借閱紀錄過多")
    logs = []
    for item in raw_logs:
        if not isinstance(item, dict):
            continue
        action = item.get("action")
        if action not in ("借書", "還書"):
            continue
        logs.append({
            "date": _clean_text(item.get("date", now_display()), "時間", 64, required=True),
            "barcode": _clean_text(item.get("barcode", ""), "條碼", 128),
            "title": _clean_text(item.get("title", ""), "書名", 200),
            "assetId": _clean_text(item.get("assetId", ""), "財產編號", 64),
            "className": _clean_text(item.get("className", ""), "班級", 50),
            "userName": _clean_text(item.get("userName", ""), "姓名", 50),
            "action": action,
        })

    return classes, member_db, books, logs


# --------------------------------------------------------------------------
# HTTP 處理
# --------------------------------------------------------------------------

class Handler(SimpleHTTPRequestHandler):
    server_version = "KindergartenLibrary/2.0"
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    # ------------------------------------------------------------------
    # 共用工具
    # ------------------------------------------------------------------

    def log_message(self, fmt, *args):
        # 靜態檔案不記錄，避免畫面被大量請求洗掉
        if getattr(self, "path", "").startswith("/api/"):
            sys.stderr.write("[%s] %s %s\n" % (
                datetime.now().strftime("%H:%M:%S"),
                self.address_string(),
                fmt % args,
            ))

    def end_headers(self):
        if not getattr(self, "path", "").startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, obj, status=200, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_api_error(self, err):
        if isinstance(err, ApiError):
            payload = {"error": err.message}
            payload.update(err.extra)
            self.send_json(payload, err.status)
        else:
            traceback.print_exc()
            self.send_json({"error": "伺服器內部錯誤"}, 500)

    def send_pdf(self, body, filename):
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition",
            'attachment; filename="report.pdf"; filename*=UTF-8\'\'{}'.format(quote(filename)),
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self, limit):
        """在路由前先把請求內容讀完，避免未授權請求留下未讀內容破壞 keep-alive。"""
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        try:
            length = int(length)
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "Content-Length 格式錯誤")
        if length < 0:
            self.close_connection = True
            raise ApiError(400, "Content-Length 格式錯誤")
        if length > limit:
            self.close_connection = True
            raise ApiError(413, "請求內容過大")
        return self.rfile.read(length) if length else b""

    def read_json(self, limit=MAX_JSON):
        raw = getattr(self, "_body_bytes", b"")
        if len(raw) > limit:
            raise ApiError(413, "請求內容過大")
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "JSON 格式錯誤")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON 內容必須是物件")
        return data

    def cookies(self):
        result = {}
        header = self.headers.get("Cookie") or ""
        for part in header.split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                result[key] = value
        return result

    def require_session(self, conn):
        token = self.cookies().get("sid")
        if not token:
            raise ApiError(401, "請先登入")
        row = conn.execute(
            "SELECT expires_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if not row or row["expires_at"] < time.time():
            raise ApiError(401, "登入已過期，請重新登入")
        return token

    # ------------------------------------------------------------------
    # 路由
    # ------------------------------------------------------------------

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path.startswith("/api/"):
                return self.handle_api("GET", path, parse_qs(parsed.query))
            return self.serve_static(path)
        except (ApiError, BrokenPipeError, ConnectionResetError) as err:
            if isinstance(err, ApiError):
                self.send_api_error(err)
        except Exception as err:  # noqa: BLE001
            self.send_api_error(err)

    def do_POST(self):
        self._mutate("POST")

    def do_PUT(self):
        self._mutate("PUT")

    def do_DELETE(self):
        self._mutate("DELETE")

    def _mutate(self, method):
        try:
            parsed = urlparse(self.path)
            if not parsed.path.startswith("/api/"):
                raise ApiError(404, "找不到資源")
            self._body_bytes = self._read_body(MAX_BODY)
            return self.handle_api(method, parsed.path, parse_qs(parsed.query))
        except (ApiError, BrokenPipeError, ConnectionResetError) as err:
            if isinstance(err, ApiError):
                self.send_api_error(err)
        except Exception as err:  # noqa: BLE001
            self.send_api_error(err)

    def do_HEAD(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/"):
                return self._not_found()
            resolved = self._resolve_static(parsed.path)
            if not resolved:
                return self._not_found()
            _, safe_path = resolved
            self.path = safe_path
            return SimpleHTTPRequestHandler.do_HEAD(self)
        except (BrokenPipeError, ConnectionResetError):
            return

    # ------------------------------------------------------------------
    # 靜態檔案
    # ------------------------------------------------------------------

    def _resolve_static(self, path):
        rel = unquote(path).lstrip("/")
        if rel == "":
            rel = "index.html"

        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if (
            not parts
            or any(p == ".." for p in parts)
            or any(p.startswith(".") for p in parts)
            or parts[0] in DENY_PREFIXES
            or parts[-1] in DENY_FILES
        ):
            return None

        full = os.path.realpath(os.path.join(BASE_DIR, *parts))
        base = os.path.realpath(BASE_DIR)
        if not (full == base or full.startswith(base + os.sep)):
            return None
        if os.path.isdir(full) or not os.path.isfile(full):
            return None
        return full, "/" + "/".join(parts)

    def serve_static(self, path):
        resolved = self._resolve_static(path)
        if not resolved:
            return self._not_found()
        _, safe_path = resolved
        self.path = safe_path
        return SimpleHTTPRequestHandler.do_GET(self)

    def _not_found(self):
        body = "404 Not Found".encode("utf-8")
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def list_directory(self, path):
        self.send_error(404, "Not Found")
        return None

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def handle_api(self, method, path, query):
        if path == "/api/health":
            if method != "GET":
                raise ApiError(405, "方法不允許")
            return self.send_json({"ok": True, "app": APP_ID, "version": BACKUP_VERSION})

        if path == "/api/login":
            if method != "POST":
                raise ApiError(405, "方法不允許")
            return self.api_login()

        if path == "/api/logout":
            if method != "POST":
                raise ApiError(405, "方法不允許")
            return self.api_logout()


        if path == "/api/session":
            if method != "GET":
                raise ApiError(405, "方法不允許")
            token = self.cookies().get("sid")
            authenticated = False
            if token:
                session_conn = connect()
                try:
                    row = session_conn.execute(
                        "SELECT expires_at FROM sessions WHERE token = ?", (token,)
                    ).fetchone()
                    authenticated = bool(row and row["expires_at"] >= time.time())
                finally:
                    session_conn.close()
            return self.send_json({"authenticated": authenticated})

        if path == "/api/password/reset":
            # 密碼自救：公開端點，本體驗以「目前管理密碼」驗證，成功後全端失效
            if method != "POST":
                raise ApiError(405, "方法不允許")
            reset_conn = connect()
            try:
                return self.api_password_reset(reset_conn)
            finally:
                reset_conn.close()

        conn = connect()
        try:
            token = self.require_session(conn)

            if path == "/api/loan-rules" and method == "GET":
                return self.send_json({
                    "student_limit": int(get_setting(conn, "loan_limit_student", "3")),
                    "teacher_limit": int(get_setting(conn, "loan_limit_teacher", "90")),
                    "student_days": int(get_setting(conn, "loan_days_student", "7")),
                    "teacher_days": int(get_setting(conn, "loan_days_teacher", "180")),
                })

            if path == "/api/loan-rules" and method == "PUT":
                data = self.read_json()
                student_limit = int(data.get("student_limit") or 0)
                teacher_limit = int(data.get("teacher_limit") or 0)
                student_days = int(data.get("student_days") or 0)
                teacher_days = int(data.get("teacher_days") or 0)
                if student_limit < 0 or teacher_limit < 0 or student_days < 0 or teacher_days < 0:
                    raise ApiError(400, "Borrowing settings cannot be negative")
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("loan_limit_student", str(student_limit)))
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("loan_limit_teacher", str(teacher_limit)))
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("loan_days_student", str(student_days)))
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("loan_days_teacher", str(teacher_days)))
                return self.send_json({"ok": True})
            if method == "GET" and path == "/api/state":
                return self.send_json(build_state(conn))

            if method == "GET" and path == "/api/backup":
                payload = build_backup(conn)
                filename = "圖書系統備份-{}.json".format(
                    datetime.now().strftime("%Y%m%d-%H%M")
                )
                body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="backup.json"; filename*=UTF-8\'\'{}'.format(
                        quote(filename)
                    ),
                )
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return

            if method == "POST" and path == "/api/backup/run":
                return self.send_json({"ok": True, "filename": run_auto_backup()})

            if method == "GET" and path == "/api/logs":
                return self.api_logs(conn, query)

            if method == "GET" and path == "/api/reservations":
                return self.api_reservations(conn, query)

            if method == "POST" and path == "/api/reservations":
                return self.api_reservation_add(conn)

            if method == "POST" and path.startswith("/api/reservations/"):
                rest = path[len("/api/reservations/"):].rstrip("/")
                if rest.endswith("/cancel"):
                    rest = rest[: -len("/cancel")].rstrip("/")
                reservation_id = unquote(rest).strip()
                if not reservation_id.isdigit():
                    raise ApiError(400, "預約編號不合法")
                return self.api_reservation_cancel(conn, int(reservation_id))

            if method == "POST" and path == "/api/logs/clear":
                return self.api_logs_clear(conn, token)

            if method == "GET" and path == "/api/report/issues":
                return self.api_report_issues(conn)

            if method == "GET" and path == "/api/report/overdue":
                return self.api_report_overdue(conn)

            if method == "GET" and path == "/api/report/stats":
                return self.api_report_stats(conn, query)

            if method == "GET" and path == "/api/report/logs.pdf":
                return self.api_report_logs_pdf(conn, query)

            if method == "GET" and path == "/api/report/inventory.pdf":
                return self.api_report_inventory_pdf(conn, query)

            if method == "GET" and path == "/api/report/checked-out.pdf":
                return self.api_report_checked_out_pdf(conn)

            if method == "GET" and path == "/api/report/issues.pdf":
                return self.api_report_issues_pdf(conn)

            if method == "GET" and path == "/api/report/member-history":
                return self.api_report_member_history(conn, query)

            if method == "GET" and path == "/api/report/member-history.pdf":
                return self.api_report_member_history_pdf(conn, query)

            if method == "GET" and path == "/api/report/stats.pdf":
                return self.api_report_stats_pdf(conn, query)

            if method == "GET" and path == "/api/report/overdue.pdf":
                return self.api_report_overdue_pdf(conn)

            if method == "GET" and path == "/api/logs.csv":
                return self.api_logs_csv(conn)

            if method == "POST" and path == "/api/import":
                return self.api_import(conn, token)

            if method == "PUT" and path == "/api/password":
                return self.api_password(conn, token)

            if method == "PUT" and path == "/api/classes":
                return self.api_classes(conn)

            if method == "POST" and path == "/api/members":
                return self.api_member_add(conn)

            if method == "DELETE" and path == "/api/members":
                return self.api_member_delete(conn, query)

            if path == "/api/loan" and method == "POST":
                return self.api_loan(conn)

            if path == "/api/loan/batch-return" and method == "POST":
                return self.api_loan_batch_return(conn)

            if path.startswith("/api/books/"):
                rest = path[len("/api/books/"):].rstrip("/")
                action = None
                if rest.endswith("/scrap") or rest.endswith("/restore"):
                    rest, action = rest.rsplit("/", 1)
                barcode = unquote(rest).strip()
                if not barcode:
                    raise ApiError(400, "條碼不可空白")
                if method == "PUT" and not action:
                    return self.api_book_upsert(conn, barcode)
                if method == "DELETE" and not action:
                    return self.api_book_delete(conn, barcode)

            if method == "POST" and path == "/api/members/import":
                return self.api_members_import(conn, token)

            if method == "POST" and path == "/api/books/import":
                return self.api_books_import(conn, token)

            if method == "GET" and path == "/api/books/search":
                return self.api_books_search(conn, query)
                if method == "POST" and action:
                    return self.api_book_action(conn, barcode, action)
                raise ApiError(405, "方法不允許")

            raise ApiError(404, "找不到 API：{}".format(path))
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # API 實作
    # ------------------------------------------------------------------

    def api_login(self):
        data = self.read_json()
        username = _clean_text(data.get("username") or data.get("userName") or "", "帳號", 50) or None
        password = data.get("password")
        if not isinstance(password, str) or not password:
            raise ApiError(400, "請輸入密碼")

        ip = self.client_address[0]
        now = time.time()
        with _lock:
            entry = _login_attempts.get(ip)
            if not entry or now - entry[1] > 300:
                entry = [0, now]
            entry[0] += 1
            _login_attempts[ip] = entry
            too_many = entry[0] > 10
        if too_many:
            raise ApiError(429, "嘗試次數過多，請 5 分鐘後再試")

        conn = connect()
        try:
            user = None
            role = "admin"
            if username:
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND active = 1",
                    (username,),
                ).fetchone()
                if not user or not verify_password(password, user["password"]):
                    raise ApiError(401, "帳號或密碼錯誤")
                role = user["role"] or "teacher"
            else:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key = 'admin_password'"
                ).fetchone()
                if not row or not verify_password(password, row["value"]):
                    raise ApiError(401, "密碼錯誤")

            with _lock:
                _login_attempts.pop(ip, None)

            token = secrets.token_urlsafe(32)
            user_id = user["id"] if user else None
            conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?", (now,)
            )
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, user_id, now, now + SESSION_TTL),
            )
            return self.send_json(
                {"ok": True, "user": {"username": username or "admin", "role": role}},
                headers={
                    "Set-Cookie": "sid={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}".format(
                        token, SESSION_TTL
                    )
                },
            )
        finally:
            conn.close()

    def api_logout(self):
        token = self.cookies().get("sid")
        if token:
            conn = connect()
            try:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            finally:
                conn.close()
        return self.send_json(
            {"ok": True},
            headers={"Set-Cookie": "sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"},
        )

    def api_logs(self, conn, query):
        try:
            page = int(query.get("page", ["1"])[0])
            page_size = int(query.get("pageSize", ["100"])[0])
        except ValueError:
            raise ApiError(400, "分頁參數錯誤")
        page = max(1, page)
        page_size = max(1, min(500, page_size))

        teacher = (query.get("teacher") or [""])[0].strip()
        year = (query.get("year") or [""])[0].strip()
        school_year = (query.get("schoolYear") or [""])[0].strip()
        conditions = []
        params = []
        if teacher:
            conditions.append("user_name = ?")
            params.append(teacher)
        if year:
            conditions.append("occurred_at LIKE ?")
            params.append(year + "%")
        if school_year:
            try:
                sy = int(school_year)
            except ValueError:
                raise ApiError(400, "學年格式錯誤")
            # 學年以民國年表示（例如 115 學年 = 2026/08/01 起至 2027/08/01 前）
            conditions.append("occurred_at >= ? AND occurred_at < ?")
            params.extend(["{}/08/01".format(sy + 1911), "{}/08/01".format(sy + 1912)])
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            "SELECT COUNT(*) FROM loan_logs" + where_sql, params
        ).fetchone()[0]
        pages = max(1, math.ceil(total / page_size))
        page = min(page, pages)
        offset = (page - 1) * page_size

        rows = conn.execute(
            "SELECT * FROM loan_logs" + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [page_size, offset],
        ).fetchall()
        return self.send_json({
            "logs": [log_json(r) for r in rows],
            "total": total,
            "page": page,
            "pages": pages,
            "pageSize": page_size,
        })

    def api_logs_clear(self, conn, token):
        cursor = conn.execute("DELETE FROM loan_logs")
        return self.send_json({"ok": True, "deleted": cursor.rowcount})

    def api_report_stats(self, conn, query):
        school_year = (query.get("schoolYear") or [""])[0].strip()
        base = " FROM loan_logs WHERE action = '借書'"
        params = []
        if school_year:
            try:
                sy = int(school_year)
            except ValueError:
                raise ApiError(400, "學年格式錯誤")
            base += " AND occurred_at >= ? AND occurred_at < ?"
            params.extend(["{}/08/01".format(sy + 1911), "{}/08/01".format(sy + 1912)])
        total = conn.execute("SELECT COUNT(*)" + base, params).fetchone()[0]
        by_class = conn.execute(
            "SELECT class_name, COUNT(*) AS n" + base + " GROUP BY class_name ORDER BY n DESC",
            params,
        ).fetchall()
        by_member = conn.execute(
            "SELECT class_name, user_name, COUNT(*) AS n" + base
            + " GROUP BY class_name, user_name ORDER BY n DESC",
            params,
        ).fetchall()
        return self.send_json({
            "schoolYear": school_year or None,
            "totalBorrows": total,
            "byClass": [
                {"className": r["class_name"] or "", "count": r["n"]} for r in by_class
            ],
            "byMember": [
                {"className": r["class_name"] or "", "userName": r["user_name"] or "", "count": r["n"]}
                for r in by_member
            ],
        })

    def _school_year_bounds(self, value):
        try:
            sy = int(value)
        except (TypeError, ValueError):
            raise ApiError(400, "學年格式錯誤")
        return "{}/08/01".format(sy + 1911), "{}/08/01".format(sy + 1912)

    def api_report_logs_pdf(self, conn, query):
        teacher = (query.get("teacher") or [""])[0].strip()
        year = (query.get("year") or [""])[0].strip()
        school_year = (query.get("schoolYear") or [""])[0].strip()
        conditions = []
        params = []
        meta = []
        if teacher:
            conditions.append("l.user_name = ?")
            params.append(teacher)
            meta.append("老師：{}".format(teacher))
        if year:
            conditions.append("l.occurred_at LIKE ?")
            params.append(year + "%")
            meta.append("年度：{}".format(year))
        if school_year:
            start, end = self._school_year_bounds(school_year)
            conditions.append("l.occurred_at >= ? AND l.occurred_at < ?")
            params.extend([start, end])
            meta.append("學年：{}".format(school_year))
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            "SELECT l.occurred_at, l.class_name, l.user_name, l.title, l.asset_id, l.action "
            "FROM loan_logs l" + where + " ORDER BY l.occurred_at DESC, l.id DESC",
            params,
        ).fetchall()
        table = [[
            r["occurred_at"], r["class_name"], r["user_name"],
            r["title"], r["asset_id"], r["action"],
        ] for r in rows]
        meta.insert(0, "列印時間：{}".format(datetime.now().strftime("%Y/%m/%d %H:%M")))
        meta.append("共 {} 筆".format(len(rows)))
        body = build_table_pdf(
            "借閱歷史紀錄", meta,
            ["時間", "班級", "姓名", "書名", "財產編號", "動作"], table,
            widths=[0.18, 0.1, 0.1, 0.32, 0.15, 0.08], landscape=True,
        )
        self.send_pdf(body, "借閱歷史紀錄-{}.pdf".format(datetime.now().strftime("%Y%m%d-%H%M")))

    def api_report_inventory_pdf(self, conn, query):
        kind = (query.get("kind") or ["all"])[0].strip()
        if kind not in ("all", "scrap"):
            raise ApiError(400, "清冊類型錯誤")
        if kind == "scrap":
            where = " WHERE status = '報廢'"
            title = "報廢清冊"
        else:
            where = " WHERE status != '報廢'"
            title = "財產清冊"
        rows = conn.execute(
            "SELECT asset_id, title, call_no, status, loaned_to, remarks FROM books"
            + where + " ORDER BY asset_id, barcode"
        ).fetchall()
        table = [[
            r["asset_id"], r["title"], r["call_no"], r["status"],
            r["loaned_to"] or "", r["remarks"] or "",
        ] for r in rows]
        meta = [
            "列印時間：{}".format(datetime.now().strftime("%Y/%m/%d %H:%M")),
            "共 {} 筆".format(len(rows)),
        ]
        body = build_table_pdf(
            title, meta,
            ["財產編號", "書名", "索書號", "狀態", "借閱人", "備註"], table,
            widths=[0.14, 0.3, 0.16, 0.1, 0.12, 0.18],
        )
        self.send_pdf(body, "{}-{}.pdf".format(title, datetime.now().strftime("%Y%m%d-%H%M")))

    def api_report_checked_out_pdf(self, conn):
        rows = conn.execute(
            "SELECT asset_id, title, call_no, loan_class, loaned_to, due_at "
            "FROM books WHERE status = '借出' ORDER BY due_at, asset_id"
        ).fetchall()
        table = [[
            r["asset_id"], r["title"], r["call_no"], r["loan_class"] or "",
            r["loaned_to"] or "", r["due_at"] or "",
        ] for r in rows]
        meta = [
            "列印時間：{}".format(datetime.now().strftime("%Y/%m/%d %H:%M")),
            "共 {} 筆".format(len(rows)),
        ]
        body = build_table_pdf(
            "圖書已借出清單", meta,
            ["財產編號", "書名", "索書號", "班級", "借閱人", "應還日期"], table,
            widths=[0.14, 0.3, 0.16, 0.12, 0.12, 0.16],
        )
        self.send_pdf(body, "已借出清單-{}.pdf".format(datetime.now().strftime("%Y%m%d-%H%M")))

    def api_report_issues_pdf(self, conn):
        rows = conn.execute(
            "SELECT asset_id, title, call_no, status, loan_class, loaned_to, remarks, updated_at "
            "FROM books WHERE status IN ('遺失', '修繕中', '爭議中') "
            "ORDER BY status, updated_at DESC, asset_id"
        ).fetchall()
        table = [[
            r["asset_id"], r["title"], r["call_no"], r["status"],
            r["loan_class"] or "", r["loaned_to"] or "", r["remarks"] or "",
            r["updated_at"] or "",
        ] for r in rows]
        meta = [
            "列印時間：{}".format(datetime.now().strftime("%Y/%m/%d %H:%M")),
            "共 {} 筆".format(len(rows)),
        ]
        body = build_table_pdf(
            "爭議／遺失／修繕狀態清冊", meta,
            ["財產編號", "書名", "索書號", "狀態", "班級", "借閱人", "備註", "更新時間"],
            table, widths=[0.12, 0.24, 0.13, 0.08, 0.1, 0.1, 0.13, 0.1], landscape=True,
        )
        self.send_pdf(body, "爭議遺失修繕清冊-{}.pdf".format(datetime.now().strftime("%Y%m%d-%H%M")))

    def _member_history_rows(self, conn, query):
        class_name = (query.get("className") or [""])[0].strip()
        user_name = (query.get("userName") or [""])[0].strip()
        school_year = (query.get("schoolYear") or [""])[0].strip()
        if not user_name:
            raise ApiError(400, "請指定姓名")
        conditions = ["l.user_name = ?"]
        params = [user_name]
        if class_name:
            conditions.append("l.class_name = ?")
            params.append(class_name)
        if school_year:
            start, end = self._school_year_bounds(school_year)
            conditions.append("l.occurred_at >= ? AND l.occurred_at < ?")
            params.extend([start, end])
        rows = conn.execute(
            "SELECT l.occurred_at, l.class_name, l.title, l.asset_id, l.action "
            "FROM loan_logs l WHERE " + " AND ".join(conditions) +
            " ORDER BY l.occurred_at ASC, l.id ASC",
            params,
        ).fetchall()
        return class_name, user_name, school_year, rows

    def api_report_member_history(self, conn, query):
        class_name, user_name, school_year, rows = self._member_history_rows(conn, query)
        logs = [{
            "date": r["occurred_at"], "className": r["class_name"], "title": r["title"],
            "assetId": r["asset_id"], "action": r["action"],
        } for r in rows]
        return self.send_json({
            "className": class_name, "userName": user_name,
            "schoolYear": school_year or None,
            "logs": logs,
            "totalBorrows": sum(1 for r in rows if r["action"] == "借書"),
            "totalReturns": sum(1 for r in rows if r["action"] == "還書"),
        })

    def api_report_member_history_pdf(self, conn, query):
        class_name, user_name, school_year, rows = self._member_history_rows(conn, query)
        table = [[r["occurred_at"], r["title"], r["asset_id"], r["action"]] for r in rows]
        meta = [
            "列印時間：{}".format(datetime.now().strftime("%Y/%m/%d %H:%M")),
            "班級：{}　姓名：{}　學年：{}".format(
                class_name or "（未指定）", user_name, school_year or "全部"
            ),
            "借書 {} 次／還書 {} 次".format(
                sum(1 for r in rows if r["action"] == "借書"),
                sum(1 for r in rows if r["action"] == "還書"),
            ),
        ]
        body = build_table_pdf(
            "個人閱讀歷程統計", meta,
            ["時間", "書名", "財產編號", "動作"], table,
            widths=[0.28, 0.42, 0.18, 0.12],
        )
        self.send_pdf(body, "個人閱讀歷程-{}-{}.pdf".format(
            user_name, datetime.now().strftime("%Y%m%d-%H%M")
        ))

    def api_report_stats_pdf(self, conn, query):
        school_year = (query.get("schoolYear") or [""])[0].strip()
        base = " FROM loan_logs WHERE action = '借書'"
        params = []
        if school_year:
            start, end = self._school_year_bounds(school_year)
            base += " AND occurred_at >= ? AND occurred_at < ?"
            params.extend([start, end])
        total = conn.execute("SELECT COUNT(*)" + base, params).fetchone()[0]
        rows = conn.execute(
            "SELECT class_name, user_name, COUNT(*) AS n" + base
            + " GROUP BY class_name, user_name ORDER BY n DESC, class_name, user_name",
            params,
        ).fetchall()
        table = [[r["class_name"] or "", r["user_name"] or "", str(r["n"])] for r in rows]
        meta = [
            "列印時間：{}".format(datetime.now().strftime("%Y/%m/%d %H:%M")),
            "學年：{}".format(school_year or "全部"),
            "全園借書總次數：{} 次".format(total),
        ]
        body = build_table_pdf(
            "全園閱讀歷程統計", meta,
            ["班級", "姓名", "借書次數"], table,
            widths=[0.4, 0.4, 0.2],
        )
        self.send_pdf(body, "全園閱讀歷程統計-{}.pdf".format(datetime.now().strftime("%Y%m%d-%H%M")))

    def api_report_overdue_pdf(self, conn):
        rows = conn.execute(
            "SELECT asset_id, title, loan_class, loaned_to, due_at "
            "FROM books WHERE status = '借出' AND due_at IS NOT NULL ORDER BY due_at ASC"
        ).fetchall()
        table = []
        now = datetime.now()
        for r in rows:
            days = ""
            if r["due_at"]:
                try:
                    due = datetime.strptime(r["due_at"], "%Y/%m/%d %H:%M:%S")
                    days = str(max(0, int((now - due).total_seconds() // 86400)))
                except ValueError:
                    days = ""
            table.append([
                r["asset_id"], r["title"], r["loan_class"] or "",
                r["loaned_to"] or "", r["due_at"] or "", days,
            ])
        meta = [
            "列印時間：{}".format(now.strftime("%Y/%m/%d %H:%M")),
            "共 {} 筆".format(len(rows)),
        ]
        body = build_table_pdf(
            "逾期未還清單", meta,
            ["財產編號", "書名", "班級", "借閱人", "應還日期", "逾期天數"], table,
            widths=[0.15, 0.3, 0.12, 0.13, 0.2, 0.1],
        )
        self.send_pdf(body, "逾期清單-{}.pdf".format(now.strftime("%Y%m%d-%H%M")))

    def api_report_issues(self, conn):
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.title = "借閱問題紀錄"
        ws.append(["時間", "班級", "姓名", "書名", "財產編號", "條碼", "動作"])
        rows = conn.execute(
            "SELECT l.occurred_at, l.class_name, l.user_name, l.title, l.asset_id, l.barcode, l.action "
            "FROM loan_logs l JOIN books b ON b.barcode = l.barcode "
            "WHERE b.status IN (?, ?, ?) ORDER BY l.occurred_at DESC",
            ("遺失", "修繕中", "爭議中"),
        ).fetchall()
        for r in rows:
            ws.append([
                r["occurred_at"], r["class_name"], r["user_name"], r["title"],
                r["asset_id"], r["barcode"], r["action"],
            ])
        buf = io.BytesIO()
        wb.save(buf)
        body = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.send_header("Content-Disposition", 'attachment; filename="borrow_issues.xlsx"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_report_overdue(self, conn):
        rows = conn.execute(
            "SELECT barcode, title, asset_id, status, loaned_to, loan_class, due_at "
            "FROM books WHERE status = '借出' AND due_at IS NOT NULL ORDER BY due_at ASC"
        ).fetchall()
        overdue = []
        for r in rows:
            due_at = None
            days_over = 0
            if r["due_at"]:
                try:
                    due_at = datetime.strptime(r["due_at"], "%Y/%m/%d %H:%M:%S")
                    days_over = max(0, int((datetime.now() - due_at).total_seconds() // 86400))
                except Exception:
                    due_at = None
            overdue.append({
                "barcode": r["barcode"],
                "title": r["title"],
                "assetId": r["asset_id"],
                "status": r["status"],
                "loanedTo": r["loaned_to"],
                "loanClass": r["loan_class"],
                "dueAt": r["due_at"],
                "daysOverdue": days_over,
            })
        return self.send_json({"overdue": overdue, "total": len(overdue)})

    def api_logs_csv(self, conn):
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(["時間", "班級", "姓名", "書名", "財產編號", "條碼", "動作"])
        for r in conn.execute("SELECT * FROM loan_logs ORDER BY id DESC"):
            writer.writerow([
                r["occurred_at"], r["class_name"], r["user_name"],
                r["title"], r["asset_id"], r["barcode"], r["action"],
            ])

        body = ("\ufeff" + output.getvalue()).encode("utf-8")
        filename = "借閱紀錄-{}.csv".format(datetime.now().strftime("%Y%m%d-%H%M"))
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition",
            'attachment; filename="loans.csv"; filename*=UTF-8\'\'{}'.format(
                quote(filename)
            ),
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def api_loan(self, conn):
        data = self.read_json()
        barcode = _clean_text(data.get("barcode"), "條碼", 128, required=True)
        action = data.get("action")
        class_name = _clean_text(data.get("className", ""), "班級", 50)
        user_name = _clean_text(data.get("userName", ""), "姓名", 50, required=True)
        if action not in ("借書", "還書"):
            raise ApiError(400, "動作必須是「借書」或「還書」")

        member_type = (data.get("memberType") or "student").strip()
        if member_type not in ("student", "teacher"):
            raise ApiError(400, "memberType must be student or teacher")
        if member_type == "teacher":
            limit = int(get_setting(conn, "loan_limit_teacher", "90"))
            loan_days = int(get_setting(conn, "loan_days_teacher", "180"))
        else:
            limit = int(get_setting(conn, "loan_limit_student", "3"))
            loan_days = int(get_setting(conn, "loan_days_student", "7"))

        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM books WHERE barcode = ?", (barcode,)
            ).fetchone()
            if not row:
                raise ApiError(404, "館藏中查不到這本書")

            if row["status"] == "報廢":
                raise ApiError(409, "《{}》已報廢，不可借還".format(row["title"]))
            if row["status"] in ("遺失", "修繕中", "爭議中"):
                raise ApiError(409, "《{}》目前狀態為「{}」，不可借出".format(row["title"], row["status"]))

            if action == "借書":
                if row["status"] == "借出" or row["loaned_to"]:
                    raise ApiError(
                        409,
                        "《{}》已被 {} 借閱中".format(row["title"], row["loaned_to"] or "他人"),
                    )

                active_count = conn.execute(
                    "SELECT COUNT(*) FROM books WHERE status = '借出' AND loaned_to = ?",
                    (user_name,),
                ).fetchone()[0]
                if active_count + 1 > limit:
                    raise ApiError(409, "《{}》借閱上限已達（{} 本），無法再借".format(row["title"], limit))

                conn.execute(
                    "UPDATE books SET status = '借出', loaned_to = ?, loan_class = ?, "
                    "due_at = ?, borrow_count = borrow_count + 1, updated_at = ? WHERE barcode = ?",
                    (user_name, class_name, (datetime.now() + timedelta(days=loan_days)).strftime("%Y/%m/%d %H:%M:%S"), now_display(), barcode),
                )
                action_text = "借書"
            else:
                if row["status"] != "借出" and not row["loaned_to"]:
                    raise ApiError(409, "《{}》目前在館內，無需歸還".format(row["title"]))
                conn.execute(
                    "UPDATE books SET status = '在館', loaned_to = NULL, loan_class = NULL, due_at = NULL, "
                    "updated_at = ? WHERE barcode = ?",
                    (now_display(), barcode),
                )
                action_text = "還書"

            cursor = conn.execute(
                "INSERT INTO loan_logs (occurred_at, barcode, title, asset_id, "
                "class_name, user_name, action) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    now_display(), barcode, row["title"], row["asset_id"],
                    class_name, user_name, action_text,
                ),
            )
            log_id = cursor.lastrowid
            # 借書成功：該成員的「待借」預約自動履約（客製化需求 4.4）
            conn.execute(
                "UPDATE reservations SET status = 'fulfilled' WHERE barcode = ? AND user_name = ? AND status = 'pending'",
                (barcode, user_name),
            )
            conn.execute("COMMIT")

            book = conn.execute(
                "SELECT * FROM books WHERE barcode = ?", (barcode,)
            ).fetchone()
            log = conn.execute(
                "SELECT * FROM loan_logs WHERE id = ?", (log_id,)
            ).fetchone()
            return self.send_json({
                "ok": True,
                "book": book_json(book),
                "log": log_json(log),
            })
        except ApiError as err:
            safe_rollback(conn)
            row = conn.execute(
                "SELECT * FROM books WHERE barcode = ?", (barcode,)
            ).fetchone()
            if row:
                err.extra["book"] = book_json(row)
            raise
        except Exception:
            safe_rollback(conn)
            raise

    def reservation_json(self, row):
        return {
            "id": row["id"],
            "createdAt": row["created_at"],
            "expiresAt": row["expires_at"],
            "barcode": row["barcode"],
            "title": row["title"],
            "assetId": row["asset_id"],
            "className": row["class_name"],
            "userName": row["user_name"],
            "memberType": row["member_type"],
            "status": row["status"],
        }

    def api_reservations(self, conn, query):
        status_filter = (query.get("status") or [""])[0].strip()
        conditions = []
        params = []
        if status_filter:
            conditions.append("status = ?")
            params.append(status_filter)
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            "SELECT * FROM reservations" + where_sql + " ORDER BY id DESC",
            params,
        ).fetchall()
        reservations = []
        for r in rows:
            reservations.append(self.reservation_json(r))
        return self.send_json({"reservations": reservations, "total": len(reservations)})

    def api_reservation_add(self, conn):
        data = self.read_json()
        barcode = _clean_text(data.get("barcode"), "條碼", 128, required=True)
        class_name = _clean_text(data.get("className", ""), "班級", 50)
        user_name = _clean_text(data.get("userName", ""), "姓名", 50, required=True)
        member_type = (data.get("memberType") or "student").strip()
        if member_type not in ("student", "teacher"):
            raise ApiError(400, "memberType must be student or teacher")
        expires_days = int(get_setting(conn, "loan_days_teacher" if member_type == "teacher" else "loan_days_student", "7"))

        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT * FROM books WHERE barcode = ?", (barcode,)).fetchone()
            if not row:
                raise ApiError(404, "館藏中查不到這本書")
            if row["status"] == "報廤":
                raise ApiError(409, "《{}》已報廤，不可預約".format(row["title"]))
            dup = conn.execute(
                "SELECT id FROM reservations WHERE barcode = ? AND user_name = ? AND status = 'pending'",
                (barcode, user_name),
            ).fetchone()
            if dup:
                raise ApiError(409, "您已有此書的進行中預約")

            now = now_display()
            expires_at = (datetime.now() + timedelta(days=expires_days)).strftime("%Y/%m/%d %H:%M:%S")
            conn.execute(
                "INSERT INTO reservations (created_at, expires_at, barcode, title, asset_id, class_name, user_name, member_type, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (now, expires_at, barcode, row["title"], row["asset_id"], class_name, user_name, member_type),
            )
            reservation_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute("COMMIT")
            res = conn.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()
            return self.send_json({"ok": True, "reservation": self.reservation_json(res)})
        except ApiError as err:
            safe_rollback(conn)
            raise
        except Exception:
            safe_rollback(conn)
            raise

    def api_reservation_cancel(self, conn, reservation_id):
        conn.execute("BEGIN IMMEDIATE")
        try:
            res = conn.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()
            if not res:
                raise ApiError(404, "找不到此預約紀錄")
            if res["status"] == "pending":
                conn.execute("UPDATE reservations SET status = 'cancelled' WHERE id = ?", (reservation_id,))
            conn.execute("COMMIT")
            res = conn.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()
            return self.send_json({"ok": True, "reservation": self.reservation_json(res)})
        except ApiError as err:
            safe_rollback(conn)
            raise
        except Exception:
            safe_rollback(conn)
            raise

    def api_loan_batch_return(self, conn):
        data = self.read_json()
        raw_barcodes = data.get("barcodes")
        if not isinstance(raw_barcodes, list) or not raw_barcodes:
            raise ApiError(400, "請提供至少一組條碼")
        barcodes = []
        for b in raw_barcodes:
            if not isinstance(b, str):
                raise ApiError(400, "條碼格式錯誤")
            code = b.strip()
            if code and code not in barcodes:
                barcodes.append(code)

        conn.execute("BEGIN IMMEDIATE")
        returned = []
        try:
            for barcode in barcodes:
                row = conn.execute("SELECT * FROM books WHERE barcode = ?", (barcode,)).fetchone()
                if not row:
                    raise ApiError(404, "館藏中查不到這本書：{}".format(barcode))
                if row["status"] != "借出" and not row["loaned_to"]:
                    raise ApiError(409, "《{}》目前在館內，無需歸還".format(row["title"]))
                conn.execute(
                    "UPDATE books SET status = '在館', loaned_to = NULL, loan_class = NULL, due_at = NULL, "
                    "updated_at = ? WHERE barcode = ?",
                    (now_display(), barcode),
                )
                conn.execute(
                    "INSERT INTO loan_logs (occurred_at, barcode, title, asset_id, class_name, user_name, action) "
                    "VALUES (?, ?, ?, ?, ?, ?, '還書')",
                    (now_display(), barcode, row["title"], row["asset_id"], row["loan_class"] or "", row["loaned_to"] or ""),
                )
                returned.append(barcode)
            conn.execute("COMMIT")
        except ApiError as err:
            safe_rollback(conn)
            raise
        except Exception:
            safe_rollback(conn)
            raise
        return self.send_json({"ok": True, "returned": returned, "total": len(returned)})

    def api_book_upsert(self, conn, barcode):
        data = self.read_json()
        title = _clean_text(data.get("title"), "書名", 200, required=True)
        asset = _clean_text(data.get("assetId", ""), "財產編號", 64)
        remarks = _clean_text(data.get("remarks") or "", "備註", 500)
        call_no = _clean_text(data.get("callNo") or data.get("call_no") or "", "索書號", 50)
        status = None
        raw_status = data.get("status")
        if isinstance(raw_status, str) and raw_status.strip():
            status = raw_status.strip()
            if status not in ("在館", "借出", "遺失", "修繕中", "爭議中", "報廢"):
                raise ApiError(400, "請求状態不合法，{}".format(status))

        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM books WHERE barcode = ?", (barcode,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE books SET title = ?, asset_id = ?, call_no = ?, remarks = ?, updated_at = ? "
                    "WHERE barcode = ?",
                    (title, asset, call_no, remarks, now_display(), barcode),
                )
                if status:
                    conn.execute(
                        "UPDATE books SET status = ? WHERE barcode = ?",
                        (status, barcode),
                    )
            else:
                conn.execute(
                    "INSERT INTO books (barcode, title, asset_id, status, remarks, call_no, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (barcode, title, asset, status or "在館", remarks, call_no, now_display(), now_display()),
                )
            conn.execute("COMMIT")
        except Exception:
            safe_rollback(conn)
            raise

        book = conn.execute(
            "SELECT * FROM books WHERE barcode = ?", (barcode,)
        ).fetchone()
        return self.send_json({"ok": True, "barcode": barcode, "book": book_json(book)})

    def api_book_action(self, conn, barcode, action):
        if action not in ("scrap", "restore"):
            raise ApiError(404, "找不到動作：{}".format(action))

        row = conn.execute(
            "SELECT * FROM books WHERE barcode = ?", (barcode,)
        ).fetchone()
        if not row:
            raise ApiError(404, "找不到此圖書")

        if action == "scrap":
            conn.execute(
                "UPDATE books SET status = '報廢', loaned_to = NULL, loan_class = NULL, "
                "updated_at = ? WHERE barcode = ?",
                (now_display(), barcode),
            )
        else:
            conn.execute(
                "UPDATE books SET status = '在館', loaned_to = NULL, loan_class = NULL, "
                "updated_at = ? WHERE barcode = ?",
                (now_display(), barcode),
            )

        book = conn.execute(
            "SELECT * FROM books WHERE barcode = ?", (barcode,)
        ).fetchone()
        return self.send_json({"ok": True, "book": book_json(book)})

    def api_book_delete(self, conn, barcode):
        row = conn.execute(
            "SELECT * FROM books WHERE barcode = ?", (barcode,)
        ).fetchone()
        if not row:
            raise ApiError(404, "找不到此圖書")
        if row["status"] != "報廢":
            raise ApiError(409, "只有已報廢的圖書可以永久刪除")
        conn.execute("DELETE FROM books WHERE barcode = ?", (barcode,))
        return self.send_json({"ok": True})

    def api_books_search(self, conn, query):
        keyword = ""
        for key in ("keyword", "q", "title", "isbn", "assetId", "barcode"):
            vals = query.get(key) or []
            if vals and vals[0].strip():
                keyword = vals[0].strip()
                break
        conditions = []
        params = []
        if keyword:
            conditions.append("(title LIKE ? OR asset_id LIKE ? OR barcode LIKE ? OR remarks LIKE ?)")
            like = "%" + keyword + "%"
            params.extend([like, like, like, like])
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            "SELECT * FROM books" + where_sql + " ORDER BY barcode",
            params,
        ).fetchall()
        groups = {}
        for r in rows:
            key = (r["title"], r["asset_id"])
            if key not in groups:
                groups[key] = {"title": r["title"], "assetId": r["asset_id"], "callNo": r["call_no"] or "", "copies": []}
            groups[key]["copies"].append({
                "barcode": r["barcode"],
                "status": r["status"],
                "loanedTo": r["loaned_to"],
                "loanClass": r["loan_class"],
                "borrowCount": r["borrow_count"],
                "remarks": r["remarks"],
                "dueAt": r["due_at"],
            })
        books = []
        for g in groups.values():
            copies = g["copies"]
            books.append({
                "title": g["title"],
                "assetId": g["assetId"],
                "callNo": g["callNo"],
                "copyCount": len(copies),
                "available": sum(1 for c in copies if c["status"] == "在館"),
                "copies": copies,
            })
        return self.send_json({"books": books, "total": len(books)})

    def api_members_import(self, conn, token):
        data = self.read_json()
        raw = data.get("members")
        if isinstance(raw, dict):
            raw = raw.get("list") or raw.get("items") or []
        if not isinstance(raw, list):
            raise ApiError(400, "批次匯入格式錯誤：members 需為陣列")

        imported = 0
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = _clean_text(item.get("name"), "姓名", 50)
            class_name = _clean_text(item.get("className") or item.get("class") or item.get("班級") or "", "班級", 50)
            member_type = _clean_text(item.get("memberType") or item.get("type") or "", "類型", 20)
            if not name or not class_name:
                continue
            row = conn.execute(
                "SELECT id FROM classes WHERE name = ? AND active = 1", (class_name,)
            ).fetchone()
            if not row:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO members (class_id, name) VALUES (?, ?)",
                (row["id"], name),
            )
            if cur.rowcount:
                imported += 1
        return self.send_json({"ok": True, "imported": imported, "total": len(raw)})

    def api_member_add(self, conn):
        data = self.read_json()
        class_name = _clean_text(data.get("className"), "班級", 50, required=True)
        name = _clean_text(data.get("name"), "姓名", 50, required=True)

        row = conn.execute(
            "SELECT id FROM classes WHERE name = ? AND active = 1", (class_name,)
        ).fetchone()
        if not row:
            raise ApiError(404, "找不到班級：{}".format(class_name))
        conn.execute(
            "INSERT OR IGNORE INTO members (class_id, name) VALUES (?, ?)",
            (row["id"], name),
        )
        return self.send_json({"ok": True, "memberDB": build_state(conn)["memberDB"]})

    def api_books_import(self, conn, token):
        data = self.read_json()
        raw = data.get("books")
        if isinstance(raw, dict):
            raw = raw.get("list") or raw.get("items") or []
        if not isinstance(raw, list):
            raise ApiError(400, "批次匯入格式錯誤：books 需為陣列")

        imported = 0
        for item in raw:
            if not isinstance(item, dict):
                continue
            barcode = _clean_text(item.get("barcode"), "條碼", 128)
            title = _clean_text(item.get("title"), "書名", 200)
            asset_id = _clean_text(item.get("assetId") or item.get("財產編號") or "", "財產編號", 64)
            status = _clean_text(item.get("status") or "在館", "狀態", 20) or "在館"
            if not barcode or not title:
                continue
            conn.execute(
                "INSERT INTO books (barcode, title, asset_id, status, remarks, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(barcode) DO UPDATE SET title = excluded.title, asset_id = excluded.asset_id, status = excluded.status, updated_at = excluded.updated_at",
                (barcode, title, asset_id, status, "", now_display(), now_display()),
            )
            imported += 1
        return self.send_json({"ok": True, "imported": imported, "total": len(raw)})

    def api_member_delete(self, conn, query):
        class_name = _clean_text(query.get("className", [""])[0], "班級", 50, required=True)
        name = _clean_text(query.get("name", [""])[0], "姓名", 50, required=True)
        conn.execute(
            "DELETE FROM members WHERE name = ? AND class_id IN "
            "(SELECT id FROM classes WHERE name = ?)",
            (name, class_name),
        )
        return self.send_json({"ok": True, "memberDB": build_state(conn)["memberDB"]})

    def api_classes(self, conn):
        data = self.read_json()
        raw = data.get("classes")
        if not isinstance(raw, list):
            raise ApiError(400, "班級清單格式錯誤")

        classes = []
        for item in raw:
            name = _clean_text(item, "班級名稱", 50)
            if name and name not in classes:
                classes.append(name)
        if not classes:
            raise ApiError(400, "班級清單不可空白")
        if len(classes) > 100:
            raise ApiError(400, "班級數量過多")

        conn.execute("BEGIN IMMEDIATE")
        try:
            existing = {
                r["name"]: r["id"]
                for r in conn.execute("SELECT id, name FROM classes")
            }
            for i, name in enumerate(classes):
                if name in existing:
                    conn.execute(
                        "UPDATE classes SET sort_order = ?, active = 1 WHERE id = ?",
                        (i, existing[name]),
                    )
                else:
                    conn.execute(
                        "INSERT INTO classes (name, sort_order, active) VALUES (?, ?, 1)",
                        (name, i),
                    )
            for name, class_id in existing.items():
                if name not in classes:
                    conn.execute(
                        "UPDATE classes SET active = 0 WHERE id = ?", (class_id,)
                    )
            conn.execute("COMMIT")
        except Exception:
            safe_rollback(conn)
            raise

        return self.send_json({"ok": True, **build_state(conn)})

    def api_password(self, conn, token):
        data = self.read_json()
        password = data.get("password")
        if not isinstance(password, str) or len(password) < 4:
            raise ApiError(400, "密碼至少需 4 個字元")
        if len(password) > 128:
            raise ApiError(400, "密碼過長")

        conn.execute(
            "UPDATE settings SET value = ? WHERE key = 'admin_password'",
            (hash_password(password),),
        )
        # 讓其他裝置的舊工作階段失效，目前這台維持登入
        conn.execute("DELETE FROM sessions WHERE token != ?", (token,))
        return self.send_json({"ok": True})

    def api_password_reset(self, conn):
        data = self.read_json()
        admin_password = data.get("adminPassword") or data.get("password")
        new_password = data.get("newPassword") or data.get("password")
        if not isinstance(admin_password, str) or not isinstance(new_password, str):
            raise ApiError(400, "請提供管理密碼與新密碼")
        if len(new_password) < 4 or len(new_password) > 128:
            raise ApiError(400, "新密碼至少需 4 個字元")
        row = conn.execute("SELECT value FROM settings WHERE key = 'admin_password'").fetchone()
        if not row or not verify_password(admin_password, row["value"]):
            raise ApiError(401, "管理密碼錯誤")
        conn.execute("UPDATE settings SET value = ? WHERE key = 'admin_password'", (hash_password(new_password),))
        conn.execute("DELETE FROM sessions")
        return self.send_json({"ok": True})

    def api_import(self, conn, token):
        data = self.read_json(limit=MAX_BODY)
        payload = data.get("data") if isinstance(data.get("data"), dict) else data
        classes, member_db, books, logs = validate_import(payload)

        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM members")
            conn.execute("DELETE FROM classes")
            conn.execute("DELETE FROM books")
            conn.execute("DELETE FROM loan_logs")

            active = set(classes)
            for cls in classes:
                conn.execute(
                    "INSERT INTO classes (name, sort_order, active) VALUES (?, ?, 1)",
                    (cls, classes.index(cls)),
                )
            # 只有成員、但不在班級清單的班級，以停用方式保留
            for cls in member_db:
                if cls not in active:
                    conn.execute(
                        "INSERT INTO classes (name, sort_order, active) VALUES (?, ?, 0)",
                        (cls, len(classes)),
                    )

            class_ids = {
                r["name"]: r["id"]
                for r in conn.execute("SELECT id, name FROM classes")
            }
            for cls, names in member_db.items():
                class_id = class_ids.get(cls)
                if not class_id:
                    continue
                for name in names:
                    conn.execute(
                        "INSERT OR IGNORE INTO members (class_id, name) VALUES (?, ?)",
                        (class_id, name),
                    )

            for barcode, book in books.items():
                conn.execute(
                    "INSERT INTO books (barcode, title, asset_id, status, loaned_to, "
                    "borrow_count, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        barcode, book["title"], book["asset_id"], book["status"],
                        book["loaned_to"], book["count"], now_display(), now_display(),
                    ),
                )

            for log in logs:
                conn.execute(
                    "INSERT INTO loan_logs (occurred_at, barcode, title, asset_id, "
                    "class_name, user_name, action) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        log["date"], log["barcode"], log["title"], log["assetId"],
                        log["className"], log["userName"], log["action"],
                    ),
                )
            conn.execute("COMMIT")
        except Exception:
            safe_rollback(conn)
            raise

        return self.send_json({"ok": True, **build_state(conn)})


# --------------------------------------------------------------------------
# 啟動
# --------------------------------------------------------------------------

def quote(value):
    from urllib.parse import quote as _quote
    return _quote(value, safe="")


def lan_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="幼兒園圖書資訊管理系統後端")
    parser.add_argument("--host", default="0.0.0.0", help="監聽位址（預設 0.0.0.0）")
    parser.add_argument("--port", type=int, default=8000, help="連接埠（預設 8000）")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite 資料庫路徑")
    parser.add_argument("--https", action="store_true", help="啟用 HTTPS")
    parser.add_argument("--cert", help="HTTPS 憑證檔（PEM）")
    parser.add_argument("--key", help="HTTPS 私鑰檔（PEM）")
    args = parser.parse_args()

    global DB_PATH
    DB_PATH = os.path.abspath(args.db)
    init_db(DB_PATH)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    threading.Thread(target=auto_backup_worker, daemon=True).start()
    httpd.daemon_threads = True

    scheme = "http"
    if args.https:
        if not (args.cert and args.key):
            parser.error("--https 需要同時提供 --cert 與 --key")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    shown_host = "localhost" if args.host in ("0.0.0.0", "::", "") else args.host
    print("=" * 56)
    print("  幼兒園圖書資訊管理系統")
    print("  資料庫：{}".format(DB_PATH))
    print("  本機：  {}://{}:{}".format(scheme, shown_host, args.port))
    if args.host in ("0.0.0.0", "::", ""):
        print("  區網：  {}://{}:{}".format(scheme, lan_ip(), args.port))
        if scheme == "http":
            print("  注意：  其他電腦以 http://IP 開啟時，瀏覽器會封鎖相機；")
            print("          相機掃碼請用本機 localhost，或改用條碼槍／HTTPS。")
    print("  預設密碼：{}（請登入後立即修改）".format(DEFAULT_PASSWORD))
    print("  按 Ctrl+C 停止")
    print("=" * 56)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n伺服器已停止")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
