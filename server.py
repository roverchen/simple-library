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
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta
from email.message import EmailMessage
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

# 忘記密碼
RESET_CODE_TTL = 10 * 60            # 驗證碼 10 分鐘內有效
RESET_MAX_ATTEMPTS = 5              # 同一組驗證碼最多嘗試 5 次
RECOVERY_RATE_WINDOW = 15 * 60      # 限流視窗（秒）
RECOVERY_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# 靜態檔案不允許存取的目錄／檔案
DENY_PREFIXES = ("data",)
DENY_FILES = {"server.py", "schema.sql", "pdf_report.py"}

_lock = threading.Lock()
_login_attempts = {}                # ip -> [count, window_start]
_recovery_attempts = {}             # bucket -> {key: [count, window_start]}


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


# --------------------------------------------------------------------------
# 忘記密碼：限流、Email、本機復原碼
# --------------------------------------------------------------------------

def rate_limit(bucket, key, limit, window=RECOVERY_RATE_WINDOW):
    """簡單的記憶體限流；達上限時回 429。成功後可用 clear_rate_limit 清除。"""
    now = time.time()
    with _lock:
        entries = _recovery_attempts.setdefault(bucket, {})
        entry = entries.get(key)
        if not entry or now - entry[1] > window:
            entry = [0, now]
        entry[0] += 1
        entries[key] = entry
        # 偶爾清掉過期紀錄，避免長期執行時無限成長
        if len(entries) > 500:
            for k, v in list(entries.items()):
                if now - v[1] > window:
                    entries.pop(k, None)
        if entry[0] > limit:
            raise ApiError(429, "嘗試次數過多，請 15 分鐘後再試")


def clear_rate_limit(bucket, key):
    with _lock:
        _recovery_attempts.get(bucket, {}).pop(key, None)


def valid_email(value):
    return bool(value) and bool(RECOVERY_EMAIL_RE.match(value)) and len(value) <= 254


def mask_email(email):
    if not email or "@" not in email:
        return ""
    name, domain = email.split("@", 1)
    if len(name) <= 1:
        shown = "*"
    else:
        shown = name[0] + "*" * (len(name) - 1)
    return "{}@{}".format(shown, domain)


def recovery_code_path(db_path=None):
    base = db_path or DB_PATH
    return os.path.join(os.path.dirname(os.path.abspath(base)), "recovery_code.txt")


def ensure_recovery_code(db_path=None):
    """確保本機復原碼存在；回傳檔案路徑。內容只寫入 data/，不會被靜態服務讀取。"""
    path = recovery_code_path(db_path)
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        code = secrets.token_hex(8)
        with open(path, "w", encoding="utf-8") as f:
            f.write(code + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path


def read_recovery_code():
    try:
        with open(recovery_code_path(), "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def regenerate_recovery_code():
    path = ensure_recovery_code()
    code = secrets.token_hex(8)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return code


def smtp_config(conn):
    try:
        port = int(get_setting(conn, "smtp_port", "587") or 587)
    except ValueError:
        port = 587
    return {
        "host": get_setting(conn, "smtp_host", ""),
        "port": port,
        "security": get_setting(conn, "smtp_security", "starttls"),
        "username": get_setting(conn, "smtp_username", ""),
        "password": get_setting(conn, "smtp_password", ""),
        "from": get_setting(conn, "smtp_from", ""),
    }


def smtp_configured(conn):
    cfg = smtp_config(conn)
    return bool(cfg["host"] and cfg["from"])


def send_recovery_email(conn, to_addr, code, username_label):
    cfg = smtp_config(conn)
    if not cfg["host"] or not cfg["from"]:
        raise ApiError(503, "尚未設定 SMTP 寄件服務，請管理員至「系統設定 → 密碼救援」填寫，或改用本機復原碼")

    msg = EmailMessage()
    msg["Subject"] = "【幼兒園圖書系統】密碼重設驗證碼"
    msg["From"] = cfg["from"]
    msg["To"] = to_addr
    msg.set_content(
        "您好：\n\n"
        "有人要求重設「{}」的密碼。\n"
        "驗證碼：{}\n\n"
        "驗證碼將在 {} 分鐘後失效，最多可嘗試 {} 次。\n"
        "如果這不是您本人的操作，請忽略本信，您的密碼不會被變更。\n\n"
        "幼兒園圖書資訊管理系統\n".format(
            username_label or "共用管理員",
            code,
            RESET_CODE_TTL // 60,
            RESET_MAX_ATTEMPTS,
        )
    )

    try:
        if cfg["security"] == "ssl":
            client = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=10)
        else:
            client = smtplib.SMTP(cfg["host"], cfg["port"], timeout=10)
        with client as smtp:
            smtp.ehlo()
            if cfg["security"] == "starttls":
                smtp.starttls()
                smtp.ehlo()
            if cfg["username"]:
                smtp.login(cfg["username"], cfg["password"])
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise ApiError(502, "寄送驗證信失敗：{}".format(exc))


def target_email(conn, username):
    """回傳 (target_key, target_id, email, label)。共用管理員使用 settings 的救援信箱。"""
    if username:
        user = find_login_user(conn, username)
        if not user:
            return None
        label = (user["name"] or "").strip() or user["username"]
        return ("user:{}".format(user["id"]), user["id"], (user["email"] or "").strip(), label)
    email = get_setting(conn, "admin_recovery_email", "").strip()
    return ("admin", None, email, "共用管理員")


def require_admin(conn, token):
    """限制救援設定與帳號管理只能由系統管理員／Root（或共用管理員）操作。"""
    row = conn.execute(
        "SELECT s.user_id, u.role FROM sessions s "
        "LEFT JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (token,),
    ).fetchone()
    if not row or row["user_id"] is None:
        return
    if (row["role"] or "") not in ("admin", "root"):
        raise ApiError(403, "需要系統管理員權限")


def require_staff(conn, token):
    """班級成員與帳號維護限教職員；學生帳號只能查看自己的資料。"""
    row = conn.execute(
        "SELECT s.user_id, u.role FROM sessions s "
        "LEFT JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (token,),
    ).fetchone()
    if not row or row["user_id"] is None:
        return
    if (row["role"] or "") not in ("admin", "root", "teacher"):
        raise ApiError(403, "需要教職員權限")


def require_permission(conn, token, perm):
    """依功能權限欄位檢查；admin/root/共用管理員一律允許，教職員與學生照旗標判斷。"""
    row = conn.execute(
        "SELECT s.user_id, u.role, u.can_loan, u.can_member, u.can_book, u.can_config, u.can_report "
        "FROM sessions s LEFT JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (token,),
    ).fetchone()
    if not row:
        raise ApiError(401, "請先登入")
    if row["user_id"] is None:
        return  # 共用管理員
    role = (row["role"] or "").strip()
    if role in ("admin", "root"):
        return
    col = "can_" + perm
    if not row[col]:
        raise ApiError(403, "此帳號未啟用「{}」功能".format(perm))


def log_audit(conn, action, actor_user_id=None, actor_name="", target="", detail="", ip=""):
    """盡力而為記錄管理操作；失敗不影響主流程（稽核紀錄只增不刪）。"""
    try:
        conn.execute(
            "INSERT INTO audit_log (occurred_at, actor_user_id, actor_name, action, target, detail, ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                actor_user_id,
                (actor_name or "")[:50],
                action,
                (target or "")[:200],
                (detail or "")[:500],
                (ip or "")[:64],
            ),
        )
    except Exception:
        pass


def session_actor(conn, token):
    """由 session token 回傳 (user_id, 顯示名稱)；共用管理員為 (None, "共用管理員")。"""
    row = conn.execute(
        "SELECT s.user_id, u.name, u.username, u.role FROM sessions s "
        "LEFT JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (token,),
    ).fetchone()
    if not row:
        return None, ""
    if row["user_id"] is None:
        return None, "共用管理員"
    return row["user_id"], (row["name"] or row["username"] or "").strip() or (row["username"] or "").strip()


def next_username(conn):
    """產生下一個未被使用的數字帳號（例如 026）。"""
    max_num = 0
    for row in conn.execute("SELECT username FROM users"):
        value = (row["username"] or "").strip()
        if value.isdigit():
            max_num = max(max_num, int(value))
    num = max_num + 1
    while True:
        candidate = "{:03d}".format(num)
        if not conn.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)).fetchone():
            return candidate
        num += 1


def ensure_member_user(conn, class_id, name, flags=None):
    """確保班級成員有對應的 users 資料列；回傳 user id。

    成員與帳號已整併到 users 表：class_id 有值即為班級成員，
    老師／管理員則為 class_id IS NULL。
    新建帳號時以 flags 套用功能權限（預設僅開借還書）；
    重新加入既有（曾停用）成員時保留原權限，不覆蓋。
    """
    row = conn.execute(
        "SELECT id FROM users WHERE class_id = ? AND name = ? ORDER BY active DESC, id LIMIT 1",
        (class_id, name),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE users SET active = 1, role = 'student', "
            "updated_at = datetime('now', 'localtime') WHERE id = ?",
            (row["id"],),
        )
        return row["id"]

    default_flags = flags if isinstance(flags, (list, tuple)) and len(flags) == 5 else (1, 0, 0, 0, 0)
    username = next_username(conn)
    cursor = conn.execute(
        "INSERT INTO users (username, name, password, role, class_id, email, active, "
        "can_loan, can_member, can_book, can_config, can_report) "
        "VALUES (?, ?, ?, 'student', ?, '', 1, ?, ?, ?, ?, ?)",
        (username, name, hash_password(DEFAULT_PASSWORD), class_id, *default_flags),
    )
    return cursor.lastrowid


def migrate_members_to_users(conn):
    """把舊版 members 資料整併進 users，之後 members 表不再使用。"""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'members'"
    ).fetchone()
    if not exists:
        return
    rows = conn.execute("SELECT class_id, name FROM members ORDER BY id").fetchall()
    for row in rows:
        ensure_member_user(conn, row["class_id"], row["name"])
    conn.execute("DROP TABLE IF EXISTS members")


def find_login_user(conn, identifier):
    """以帳號、Email（不分大小寫）或姓名找出啟用中的帳號。"""
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND active = 1",
        (identifier,),
    ).fetchone()
    if user:
        return user

    matches = conn.execute(
        "SELECT * FROM users WHERE email <> '' AND lower(email) = lower(?) AND active = 1",
        (identifier,),
    ).fetchall()
    if len(matches) > 1:
        raise ApiError(409, "此 Email 對應多個帳號，請改用帳號登入")
    if matches:
        return matches[0]

    matches = conn.execute(
        "SELECT * FROM users WHERE name <> '' AND name = ? AND active = 1",
        (identifier,),
    ).fetchall()
    if len(matches) > 1:
        raise ApiError(409, "此姓名對應多個帳號，請改用帳號或 Email 登入")
    return matches[0] if matches else None


def init_db(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    schema_path = os.path.join(BASE_DIR, "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = f.read()

    conn = connect(db_path)
    try:
        conn.executescript(schema)
        conn.execute("PRAGMA user_version = 1")

        # 預約排隊機制（v2.1）：舊版 CHECK 只允許 pending/cancelled/fulfilled，
        # 新增 ready（已歸還可來取書）與 expired（逾期未取）狀態 → 需要重建表
        legacy = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'reservations'"
        ).fetchone()
        if legacy and legacy["sql"] and "'ready'" not in legacy["sql"]:
            conn.executescript(
                """
                BEGIN;
                ALTER TABLE reservations RENAME TO reservations_legacy;
                CREATE TABLE reservations (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                    expires_at  TEXT,
                    barcode     TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    asset_id    TEXT NOT NULL DEFAULT '',
                    class_name  TEXT NOT NULL,
                    user_name   TEXT NOT NULL,
                    member_type TEXT NOT NULL DEFAULT 'student',
                    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'cancelled', 'fulfilled', 'ready', 'expired'))
                );
                INSERT INTO reservations (id, created_at, expires_at, barcode, title, asset_id, class_name, user_name, member_type, status)
                    SELECT id, created_at, expires_at, barcode, title, asset_id, class_name, user_name, member_type, status
                    FROM reservations_legacy;
                DROP TABLE reservations_legacy;
                CREATE INDEX IF NOT EXISTS idx_reservations_barcode ON reservations (barcode, status);
                CREATE INDEX IF NOT EXISTS idx_reservations_user ON reservations (user_name, status);
                COMMIT;
                """
            )

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

        try:
            conn.execute("ALTER TABLE books ADD COLUMN isbn TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE users ADD COLUMN class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL")
        except Exception:
            pass

        # 權限欄位：借還書/班級成員/圖書管理/系統設定/報表列印
        for col in ("can_loan", "can_member", "can_book", "can_config", "can_report"):
            try:
                conn.execute("ALTER TABLE users ADD COLUMN {} INTEGER DEFAULT 0".format(col))
            except Exception:
                pass

        # 現有帳號預設權限：僅在首次導入權限欄位時設定一次，避免每次啟動覆蓋管理員的自訂設定。
        # 所有啟用帳號一律可使用借還書畫面（含學生；規格「學生帳號僅能登入使用借還書」），
        # 其餘系統功能照舊：教職員可由管理員勾選、學生不開放。
        migrated = conn.execute(
            "SELECT value FROM settings WHERE key = 'permissions_migrated'"
        ).fetchone()
        if not migrated:
            for r in conn.execute("SELECT id, role FROM users").fetchall():
                if (r["role"] or "") in ("admin", "root"):
                    conn.execute(
                        "UPDATE users SET can_loan = 1, can_member = 1, can_book = 1, can_config = 1, can_report = 1 WHERE id = ?",
                        (r["id"],),
                    )
                else:
                    conn.execute(
                        "UPDATE users SET can_loan = 1, can_member = 0, can_book = 0, can_config = 0, can_report = 0 WHERE id = ?",
                        (r["id"],),
                    )
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('permissions_migrated', '1')"
            )

        # 把舊版 members 整併進 users（班級成員＝class_id 有值的帳號）。
        migrate_members_to_users(conn)

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

    # 首次啟動即建立本機復原碼（檔案權限 600），供 Email 無法使用時救援。
    ensure_recovery_code(db_path)


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
        "isbn": row["isbn"] or "",
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
        "SELECT c.name AS cls, u.name AS member "
        "FROM users u JOIN classes c ON c.id = u.class_id "
        "WHERE u.active = 1 "
        "ORDER BY c.sort_order, c.id, u.id"
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
        isbn = _clean_text(book.get("isbn") or book.get("ISBN") or "", "ISBN", 32)
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
            "isbn": isbn,
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
            user_info = None
            if token:
                session_conn = connect()
                try:
                    row = session_conn.execute(
                        "SELECT s.expires_at, s.user_id, u.username, u.name, u.role, "
                        "u.can_loan, u.can_member, u.can_book, u.can_config, u.can_report "
                        "FROM sessions s LEFT JOIN users u ON u.id = s.user_id "
                        "WHERE s.token = ?", (token,)
                    ).fetchone()
                    if row and row["expires_at"] >= time.time():
                        authenticated = True
                        if row["user_id"] is None:
                            user_info = {
                                "username": "admin",
                                "name": "",
                                "role": "admin",
                                "permissions": {
                                    "canLoan": True, "canMember": True, "canBook": True,
                                    "canConfig": True, "canReport": True,
                                },
                            }
                        else:
                            role = row["role"] or "teacher"
                            if role in ("admin", "root"):
                                perms = {"canLoan": True, "canMember": True, "canBook": True,
                                         "canConfig": True, "canReport": True}
                            else:
                                perms = {
                                    "canLoan": bool(row["can_loan"]),
                                    "canMember": bool(row["can_member"]),
                                    "canBook": bool(row["can_book"]),
                                    "canConfig": bool(row["can_config"]),
                                    "canReport": bool(row["can_report"]),
                                }
                            user_info = {
                                "username": row["username"] or "",
                                "name": row["name"] or "",
                                "role": role,
                                "permissions": perms,
                            }
                finally:
                    session_conn.close()
            resp = {"authenticated": authenticated}
            if user_info:
                resp["user"] = user_info
            return self.send_json(resp)

        if path == "/api/password/reset":
            # 舊版：以「目前管理密碼」驗證後換新密碼（保留相容）
            if method != "POST":
                raise ApiError(405, "方法不允許")
            reset_conn = connect()
            try:
                return self.api_password_reset(reset_conn)
            finally:
                reset_conn.close()

        # 忘記密碼：以下為公開端點，不需登入
        if path == "/api/password/recovery-info" and method == "GET":
            public_conn = connect()
            try:
                return self.api_recovery_info(public_conn, query)
            finally:
                public_conn.close()

        if path == "/api/password/forgot/request" and method == "POST":
            public_conn = connect()
            try:
                return self.api_forgot_request(public_conn)
            finally:
                public_conn.close()

        if path == "/api/password/forgot/verify" and method == "POST":
            public_conn = connect()
            try:
                return self.api_forgot_verify(public_conn)
            finally:
                public_conn.close()

        if path == "/api/password/recovery-code" and method == "POST":
            public_conn = connect()
            try:
                return self.api_recovery_code(public_conn)
            finally:
                public_conn.close()

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
                require_permission(conn, token, "config")
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
                _audit_id, _audit_name = session_actor(conn, token)
                log_audit(conn, "修改借閱規則", _audit_id, _audit_name,
                          detail="學生 {} 本／{} 天；教職員 {} 本／{} 天".format(
                              student_limit, student_days, teacher_limit, teacher_days),
                          ip=self.client_address[0])
                return self.send_json({"ok": True})
            if method == "GET" and path == "/api/state":
                return self.send_json(build_state(conn))

            if method == "GET" and path == "/api/backup":
                require_admin(conn, token)
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
                require_admin(conn, token)
                filename = run_auto_backup()
                _audit_id, _audit_name = session_actor(conn, token)
                log_audit(conn, "手動備份", _audit_id, _audit_name,
                          target=filename or "", detail="手動執行自動備份",
                          ip=self.client_address[0])
                return self.send_json({"ok": True, "filename": filename})

            if method == "GET" and path == "/api/logs":
                require_permission(conn, token, "report")
                return self.api_logs(conn, query)

            if method == "GET" and path == "/api/reservations":
                require_permission(conn, token, "loan")
                return self.api_reservations(conn, query)

            if method == "POST" and path == "/api/reservations":
                require_permission(conn, token, "loan")
                return self.api_reservation_add(conn, token)

            if method == "POST" and path.startswith("/api/reservations/"):
                require_permission(conn, token, "loan")
                rest = path[len("/api/reservations/"):].rstrip("/")
                if rest.endswith("/cancel"):
                    rest = rest[: -len("/cancel")].rstrip("/")
                reservation_id = unquote(rest).strip()
                if not reservation_id.isdigit():
                    raise ApiError(400, "預約編號不合法")
                return self.api_reservation_cancel(conn, int(reservation_id), token)

            if method == "POST" and path == "/api/logs/clear":
                require_permission(conn, token, "report")
                return self.api_logs_clear(conn, token)

            if method == "GET" and path == "/api/report/issues":
                require_permission(conn, token, "report")
                return self.api_report_issues(conn)

            if method == "GET" and path == "/api/report/overdue":
                require_permission(conn, token, "report")
                return self.api_report_overdue(conn)

            if method == "GET" and path == "/api/report/stats":
                require_permission(conn, token, "report")
                return self.api_report_stats(conn, query)

            if method == "GET" and path == "/api/report/logs.pdf":
                require_permission(conn, token, "report")
                return self.api_report_logs_pdf(conn, query)

            if method == "GET" and path == "/api/report/inventory.pdf":
                require_permission(conn, token, "report")
                return self.api_report_inventory_pdf(conn, query)

            if method == "GET" and path == "/api/report/checked-out.pdf":
                require_permission(conn, token, "report")
                return self.api_report_checked_out_pdf(conn)

            if method == "GET" and path == "/api/report/issues.pdf":
                require_permission(conn, token, "report")
                return self.api_report_issues_pdf(conn)

            if method == "GET" and path == "/api/report/member-history":
                require_permission(conn, token, "report")
                return self.api_report_member_history(conn, query)

            if method == "GET" and path == "/api/report/member-history.pdf":
                require_permission(conn, token, "report")
                return self.api_report_member_history_pdf(conn, query)

            if method == "GET" and path == "/api/report/stats.pdf":
                require_permission(conn, token, "report")
                return self.api_report_stats_pdf(conn, query)

            if method == "GET" and path == "/api/report/overdue.pdf":
                require_permission(conn, token, "report")
                return self.api_report_overdue_pdf(conn)

            if method == "GET" and path == "/api/audit":
                require_permission(conn, token, "config")
                return self.api_audit(conn, query)

            if method == "GET" and path == "/api/audit.csv":
                require_permission(conn, token, "config")
                return self.api_audit_csv(conn, query)

            if method == "GET" and path == "/api/logs.csv":
                require_permission(conn, token, "report")
                return self.api_logs_csv(conn, query)

            if method == "POST" and path == "/api/import":
                require_admin(conn, token)
                return self.api_import(conn, token)

            if path == "/api/settings/recovery":
                require_admin(conn, token)
                if method == "GET":
                    return self.api_recovery_settings_get(conn)
                if method == "PUT":
                    return self.api_recovery_settings_put(conn)

            if path == "/api/accounts":
                require_admin(conn, token)
                if method == "GET":
                    return self.api_accounts_list(conn)
                if method == "POST":
                    return self.api_account_upsert(conn, None)

            if path.startswith("/api/accounts/"):
                require_admin(conn, token)
                rest = path[len("/api/accounts/"):].rstrip("/")
                if rest.endswith("/reset-password"):
                    account_id = unquote(rest[: -len("/reset-password")].rstrip("/")).strip()
                    if method != "POST" or not account_id.isdigit():
                        raise ApiError(400, "帳號編號不合法")
                    return self.api_account_reset_password(conn, int(account_id))
                account_id = unquote(rest).strip()
                if method == "PUT" and account_id.isdigit():
                    return self.api_account_upsert(conn, int(account_id))
                raise ApiError(404, "找不到帳號 API")

            if method == "POST" and path == "/api/recovery-code/regenerate":
                require_admin(conn, token)
                return self.api_recovery_code_regenerate()

            if method == "PUT" and path == "/api/password":
                require_admin(conn, token)
                return self.api_password(conn, token)

            if method == "PUT" and path == "/api/classes":
                require_admin(conn, token)
                return self.api_classes(conn, token)

            if path == "/api/member-accounts":
                require_staff(conn, token)
                require_permission(conn, token, "member")
                if method != "GET":
                    raise ApiError(405, "方法不允許")
                return self.api_member_accounts_list(conn)

            if path.startswith("/api/member-accounts/"):
                require_staff(conn, token)
                require_permission(conn, token, "member")
                rest = path[len("/api/member-accounts/"):].rstrip("/")
                if rest.endswith("/reset-password"):
                    account_id = unquote(rest[: -len("/reset-password")].rstrip("/")).strip()
                    if method != "POST" or not account_id.isdigit():
                        raise ApiError(400, "成員編號不合法")
                    return self.api_member_account_reset_password(conn, int(account_id), token)
                account_id = unquote(rest).strip()
                if not account_id.isdigit():
                    raise ApiError(400, "成員編號不合法")
                if method == "PUT":
                    return self.api_member_account_update(conn, int(account_id), token)
                if method == "DELETE":
                    return self.api_member_account_delete(conn, int(account_id), token)
                raise ApiError(404, "找不到成員帳號 API")

            if method == "POST" and path == "/api/members":
                require_staff(conn, token)
                require_permission(conn, token, "member")
                return self.api_member_add(conn, token)

            if method == "DELETE" and path == "/api/members":
                require_staff(conn, token)
                require_permission(conn, token, "member")
                return self.api_member_delete(conn, query, token)

            if path == "/api/loan" and method == "POST":
                require_permission(conn, token, "loan")
                return self.api_loan(conn)

            if path == "/api/loan/batch-return" and method == "POST":
                require_permission(conn, token, "loan")
                return self.api_loan_batch_return(conn, token)

            if path.startswith("/api/books/"):
                rest = path[len("/api/books/"):].rstrip("/")
                action = None
                if rest.endswith("/scrap") or rest.endswith("/restore"):
                    rest, action = rest.rsplit("/", 1)
                barcode = unquote(rest).strip()
                if not barcode:
                    raise ApiError(400, "條碼不可空白")
                if method == "PUT" and not action:
                    require_permission(conn, token, "book")
                    return self.api_book_upsert(conn, barcode, token)
                if method == "DELETE" and not action:
                    require_permission(conn, token, "book")
                    return self.api_book_delete(conn, barcode, token)
                if method == "POST" and action:
                    require_permission(conn, token, "book")
                    return self.api_book_action(conn, barcode, action, token)

            if method == "POST" and path == "/api/members/import":
                require_staff(conn, token)
                require_permission(conn, token, "member")
                return self.api_members_import(conn, token)

            if method == "POST" and path == "/api/books/import":
                require_permission(conn, token, "book")
                return self.api_books_import(conn, token)

            if method == "GET" and path == "/api/books/search":
                require_permission(conn, token, "book")
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

    def _audit(self, conn, token, action, target="", detail=""):
        actor_id, actor_name = session_actor(conn, token)
        log_audit(conn, action, actor_id, actor_name, target=target, detail=detail,
                  ip=(self.client_address[0] if self.client_address else ""))

    def api_audit(self, conn, query):
        try:
            page = int(query.get("page", ["1"])[0])
            page_size = int(query.get("pageSize", ["100"])[0])
        except ValueError:
            raise ApiError(400, "分頁參數錯誤")
        page = max(1, page)
        page_size = max(1, min(500, page_size))
        action = (query.get("action") or [""])[0].strip()[:50]
        conditions, params = [], []
        if action:
            conditions.append("action = ?")
            params.append(action)
        date_conds, date_params, _ = self._date_range_conds(query)
        conditions.extend(date_conds)
        params.extend(date_params)
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            "SELECT COUNT(*) FROM audit_log" + where_sql, params
        ).fetchone()[0]
        pages = max(1, math.ceil(total / page_size))
        page = min(page, pages)
        offset = (page - 1) * page_size

        rows = conn.execute(
            "SELECT * FROM audit_log" + where_sql +
            " ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [page_size, offset],
        ).fetchall()
        return self.send_json({
            "logs": [{
                "id": r["id"],
                "occurredAt": r["occurred_at"],
                "actor": r["actor_name"] or "（未知）",
                "action": r["action"],
                "target": r["target"] or "",
                "detail": r["detail"] or "",
                "ip": r["ip"] or "",
            } for r in rows],
            "total": total,
            "page": page,
            "pages": pages,
            "pageSize": page_size,
        })

    def api_audit_csv(self, conn, query):
        action = (query.get("action") or [""])[0].strip()[:50]
        conditions, params = [], []
        if action:
            conditions.append("action = ?")
            params.append(action)
        date_conds, date_params, _ = self._date_range_conds(query)
        conditions.extend(date_conds)
        params.extend(date_params)
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(["時間", "操作人", "動作", "目標", "內容", "IP"])
        for r in conn.execute(
            "SELECT * FROM audit_log" + where_sql + " ORDER BY id DESC",
            params,
        ):
            writer.writerow([
                r["occurred_at"], r["actor_name"] or "", r["action"],
                r["target"] or "", r["detail"] or "", r["ip"] or "",
            ])
        body = ("\ufeff" + output.getvalue()).encode("utf-8")
        filename = "稽核紀錄-{}.csv".format(datetime.now().strftime("%Y%m%d-%H%M"))
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition",
            'attachment; filename="audit.csv"; filename*=UTF-8\'\'{}'.format(
                quote(filename)
            ),
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

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
                # 登入識別碼依序比對：帳號（完全相符）→ Email（不分大小寫）→ 姓名（完全相符）
                user = find_login_user(conn, username)
                if not user or not verify_password(password, user["password"]):
                    log_audit(conn, "登入失敗", None, username or "",
                              detail="帳號或密碼錯誤", ip=ip)
                    raise ApiError(401, "帳號或密碼錯誤")
                role = user["role"] or "teacher"
            else:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key = 'admin_password'"
                ).fetchone()
                if not row or not verify_password(password, row["value"]):
                    log_audit(conn, "登入失敗", None, "共用管理員",
                              detail="密碼錯誤", ip=ip)
                    raise ApiError(401, "密碼錯誤")

            with _lock:
                _login_attempts.pop(ip, None)

            token = secrets.token_urlsafe(32)
            user_id = user["id"] if user else None
            # 讀取該帳號的各功能權限
            if user is None:
                # 共用管理員（admin）擁有全部功能權限
                perms = {
                    "canLoan": True,
                    "canMember": True,
                    "canBook": True,
                    "canConfig": True,
                    "canReport": True,
                }
            else:
                prow = conn.execute(
                    "SELECT can_loan, can_member, can_book, can_config, can_report, role FROM users WHERE id = ?",
                    (user["id"],),
                ).fetchone()
                if prow and (prow["role"] or "") in ("admin", "root"):
                    perms = {
                        "canLoan": True,
                        "canMember": True,
                        "canBook": True,
                        "canConfig": True,
                        "canReport": True,
                    }
                elif prow:
                    perms = {
                        "canLoan": bool(prow["can_loan"]),
                        "canMember": bool(prow["can_member"]),
                        "canBook": bool(prow["can_book"]),
                        "canConfig": bool(prow["can_config"]),
                        "canReport": bool(prow["can_report"]),
                    }
                else:
                    perms = {
                        "canLoan": True,
                        "canMember": False,
                        "canBook": False,
                        "canConfig": False,
                        "canReport": False,
                    }
            conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?", (now,)
            )
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, user_id, now, now + SESSION_TTL),
            )
            log_audit(
                conn, "登入", user_id,
                (user["name"] or user["username"] if user else "共用管理員"),
                target=(user["username"] if user else "共用管理員"),
                ip=self.client_address[0],
            )
            return self.send_json(
                {
                    "ok": True,
                    "user": {
                        "username": (user["username"] if user else "admin"),
                        "name": (user["name"] if user else "") or "",
                        "role": role,
                        "permissions": perms,
                    },
                },
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
        date_conds, date_params, _ = self._date_range_conds(query)
        conditions.extend(date_conds)
        params.extend(date_params)
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
        self._audit(conn, token, "清除借閱紀錄",
                    detail="已清除 {} 筆借閱紀錄".format(cursor.rowcount))
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

    def _date_range_conds(self, query, prefix=""):
        """解析 dateFrom／dateTo（YYYY-MM-DD 或 YYYY/MM/DD）為 occurred_at 條件。"""
        raw_from = (query.get("dateFrom") or [""])[0].strip().replace("-", "/")
        raw_to = (query.get("dateTo") or [""])[0].strip().replace("-", "/")
        conds, params, meta = [], [], []

        def parse_date(s, label):
            m = re.fullmatch(r"(\d{4})/(\d{2})/(\d{2})", s)
            if not m:
                raise ApiError(400, "{}格式錯誤（請用 西元/月/日）".format(label))
            y, mo, d = (int(g) for g in m.groups())
            try:
                datetime(y, mo, d)
            except ValueError:
                raise ApiError(400, "{}不存在（如 2026/02/31）".format(label))
            return "{:04d}/{:02d}/{:02d}".format(y, mo, d)

        start = parse_date(raw_from, "起始日期") if raw_from else None
        end = parse_date(raw_to, "結束日期") if raw_to else None
        if start and end and start > end:
            raise ApiError(400, "起始日期不可晚於結束日期")
        if start:
            conds.append("{}occurred_at >= ?".format(prefix))
            params.append(start + " 00:00:00")
        if end:
            # 結束日含當天：occurred_at < 次日 00:00
            next_day = (
                datetime(int(end[:4]), int(end[5:7]), int(end[8:10])) +
                timedelta(days=1)
            ).strftime("%Y/%m/%d %H:%M:%S")
            conds.append("{}occurred_at < ?".format(prefix))
            params.append(next_day)
        if start or end:
            meta.append("期間：{} ～ {}".format(start or "最初", end or "今日"))
        return conds, params, meta

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
        date_conds, date_params, date_meta = self._date_range_conds(query, prefix="l.")
        conditions.extend(date_conds)
        params.extend(date_params)
        meta.extend(date_meta)
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

    def api_logs_csv(self, conn, query):
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(["時間", "班級", "姓名", "書名", "財產編號", "條碼", "動作"])
        teacher = (query.get("teacher") or [""])[0].strip()
        year = (query.get("year") or [""])[0].strip()
        school_year = (query.get("schoolYear") or [""])[0].strip()
        conditions, params = [], []
        if teacher:
            conditions.append("user_name = ?")
            params.append(teacher)
        if year:
            conditions.append("occurred_at LIKE ?")
            params.append(year + "%")
        if school_year:
            start, end = self._school_year_bounds(school_year)
            conditions.append("occurred_at >= ? AND occurred_at < ?")
            params.extend([start, end])
        date_conds, date_params, _ = self._date_range_conds(query)
        conditions.extend(date_conds)
        params.extend(date_params)
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        for r in conn.execute(
            "SELECT * FROM loan_logs" + where_sql + " ORDER BY id DESC",
            params,
        ):
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
            # 先惰性清理逾期預約，讓候取狀態與排隊順位正確
            self.expire_reservations(conn)
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
                # 多人候取中的書：僅輪到的人可先借閱
                ready = conn.execute(
                    "SELECT * FROM reservations WHERE barcode = ? AND status = 'ready'",
                    (barcode,),
                ).fetchone()
                if ready and (ready["user_name"] or "") != user_name:
                    raise ApiError(
                        409,
                        "《{}》已由 {}（{}）預約候取，請先等候取書或逾期未取再排隊".format(
                            row["title"], ready["user_name"], ready["class_name"] or ""
                        ),
                    )
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
            promoted = []
            if action == "借書":
                # 借書成功：優先履約「可取書(ready)」狀態的自己預約，其次履約自己最早的 pending 預約
                my_reservation = conn.execute(
                    "SELECT * FROM reservations WHERE barcode = ? AND user_name = ? AND status = 'ready' "
                    "ORDER BY id ASC LIMIT 1",
                    (barcode, user_name),
                ).fetchone() or conn.execute(
                    "SELECT * FROM reservations WHERE barcode = ? AND user_name = ? AND status = 'pending' "
                    "ORDER BY id ASC LIMIT 1",
                    (barcode, user_name),
                ).fetchone()
                if my_reservation:
                    conn.execute("UPDATE reservations SET status = 'fulfilled' WHERE id = ?", (my_reservation["id"],))
            else:
                # 還書：佇列下一位自動遞補為候取狀態
                promoted = self._promote_ready(conn, [barcode])
            conn.execute("COMMIT")

            # 完成一筆借還書後，自動為教職員開啟「報表」權限，讓老師能看到報表頁籤。
            try:
                self._grant_report_auto(conn)
            except Exception:
                pass

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
                "promoted": promoted,
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

    def _grant_report_auto(self, conn):
        """教職員首次完成借還書後自動開啟報表權限；已開啟或其他角色不變動。"""
        token = self.cookies().get("sid")
        row = conn.execute(
            "SELECT s.user_id, u.role, u.can_report FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
        ).fetchone()
        if (
            row
            and (row["role"] or "") == "teacher"
            and not row["can_report"]
        ):
            conn.execute(
                "UPDATE users SET can_report = 1, "
                "updated_at = datetime('now', 'localtime') WHERE id = ?",
                (row["user_id"],),
            )

    def expire_reservations(self, conn):
        """惰性清理：待履約超過 expires_at → cancelled；可取書超過期限 → expired（再由歸還/取消/排隊邏輯往後推）。"""
        expired_barcodes = [
            r["barcode"] for r in conn.execute(
                "SELECT DISTINCT barcode FROM reservations "
                "WHERE status = 'ready' AND expires_at IS NOT NULL AND expires_at < ?",
                (now_display(),),
            ).fetchall()
        ]
        conn.execute(
            "UPDATE reservations SET status = 'cancelled' "
            "WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at < ?",
            (now_display(),),
        )
        conn.execute(
            "UPDATE reservations SET status = 'expired' "
            "WHERE status = 'ready' AND expires_at IS NOT NULL AND expires_at < ?",
            (now_display(),),
        )
        # 排隊中下一位等著取書：每條書若書在館且還沒有 ready 預約，補到 ready 狀態
        for barcode in expired_barcodes:
            self._promote_ready(conn, [barcode])

    def _queue_by_barcode(self, conn):
        """回傳 {barcode: [rows...]}（只含 pending／ready，依 id 由舊到新）。"""
        groups = {}
        for r in conn.execute(
            "SELECT * FROM reservations WHERE status IN ('pending', 'ready') ORDER BY barcode, id"
        ).fetchall():
            groups.setdefault(r["barcode"], []).append(r)
        return groups

    def _reservation_positions(self, conn):
        """回傳 {id: 順位}（同一本書內依 id 順序）。"""
        positions = {}
        for barcode, rows in self._queue_by_barcode(conn).items():
            for i, r in enumerate(rows, start=1):
                positions[r["id"]] = i
        return positions

    def _promote_ready(self, conn, barcodes):
        """歸還後把每條 barcode 的下一位 pending 預約改為 ready（可來取書）；書不在館則不遞補。"""
        promoted = []
        if isinstance(barcodes, str):
            barcodes = [barcodes]
        for barcode in barcodes:
            book = conn.execute(
                "SELECT status FROM books WHERE barcode = ?", (barcode,)
            ).fetchone()
            if not book or book["status"] != "在館":
                continue
            exists_ready = conn.execute(
                "SELECT 1 FROM reservations WHERE barcode = ? AND status = 'ready'",
                (barcode,),
            ).fetchone()
            if exists_ready:
                continue
            nxt = conn.execute(
                "SELECT * FROM reservations WHERE barcode = ? AND status = 'pending' ORDER BY id ASC LIMIT 1",
                (barcode,),
            ).fetchone()
            if not nxt:
                continue
            days = int(get_setting(
                conn,
                "loan_days_teacher" if nxt["member_type"] == "teacher" else "loan_days_student",
                "7",
            ))
            expires_at = (datetime.now() + timedelta(days=days)).strftime("%Y/%m/%d %H:%M:%S")
            conn.execute(
                "UPDATE reservations SET status = 'ready', expires_at = ? WHERE id = ? AND status = 'pending'",
                (expires_at, nxt["id"]),
            )
            promoted.append({
                "id": nxt["id"],
                "userName": nxt["user_name"],
                "className": nxt["class_name"],
                "title": nxt["title"],
                "expiresAt": expires_at,
            })
        return promoted

    def reservation_json(self, row, positions=None):
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
            "queuePos": (positions or {}).get(row["id"]),
        }

    def api_reservations(self, conn, query):
        # 過期預約自動失效，避免清單累積永遠不會成立的「進行中」預約
        self.expire_reservations(conn)
        status_filter = (query.get("status") or [""])[0].strip()
        conditions = []
        params = []
        if status_filter == "active":
            conditions.append("status IN ('pending', 'ready')")
        elif status_filter:
            conditions.append("status = ?")
            params.append(status_filter)
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        positions = self._reservation_positions(conn)
        rows = conn.execute(
            "SELECT * FROM reservations" + where_sql +
            " ORDER BY CASE WHEN status = 'ready' THEN 0 ELSE 1 END, id DESC",
            params,
        ).fetchall()
        reservations = []
        for r in rows:
            reservations.append(self.reservation_json(r, positions))
        return self.send_json({"reservations": reservations, "total": len(reservations)})

    def api_reservation_add(self, conn, token=None):
        data = self.read_json()
        barcode = _clean_text(data.get("barcode"), "條碼", 128, required=True)
        class_name = _clean_text(data.get("className", ""), "班級", 50)
        user_name = _clean_text(data.get("userName", ""), "姓名", 50, required=True)
        member_type = (data.get("memberType") or "student").strip()
        if member_type not in ("student", "teacher"):
            raise ApiError(400, "memberType must be student or teacher")
        expires_days = int(get_setting(conn, "loan_days_teacher" if member_type == "teacher" else "loan_days_student", "7"))

        conn.execute("BEGIN IMMEDIATE")
        # 先清掉逾期預約，讓排隊順序準確
        self.expire_reservations(conn)
        try:
            row = conn.execute("SELECT * FROM books WHERE barcode = ?", (barcode,)).fetchone()
            if not row:
                raise ApiError(404, "館藏中查不到這本書")
            if row["status"] == "報廢":
                raise ApiError(409, "《{}》已報廢，不可預約".format(row["title"]))
            if row["status"] != "借出" or not row["loaned_to"]:
                raise ApiError(409, "《{}》目前在館，無需預約".format(row["title"]))
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
            # 排隊順位可在同一 transaction 內算出（書仍為借出狀態，佇列依 id 排序）
            positions = self._reservation_positions(conn)
            conn.execute("COMMIT")
            self._audit(conn, token, "新增預約", target=barcode,
                        detail="{}（{}）".format(row["title"] or "", user_name))
            res = conn.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()
            return self.send_json({"ok": True, "reservation": self.reservation_json(res, positions)})
        except ApiError as err:
            safe_rollback(conn)
            raise
        except Exception:
            safe_rollback(conn)
            raise

    def api_reservation_cancel(self, conn, reservation_id, token=None):
        conn.execute("BEGIN IMMEDIATE")
        self.expire_reservations(conn)
        try:
            res = conn.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()
            if not res:
                raise ApiError(404, "找不到此預約紀錄")
            cancelled_ready = res["status"] == "ready"
            if res["status"] in ("pending", "ready"):
                conn.execute("UPDATE reservations SET status = 'cancelled' WHERE id = ? AND status IN ('pending', 'ready')", (reservation_id,))
                self._audit(conn, token, "取消預約", target=res["barcode"],
                            detail="{}（{}）".format(res["title"] or "", res["user_name"] or ""))
            # 取消的是候取中的預約 → 排隊下一位往前遞補
            if cancelled_ready:
                self._promote_ready(conn, [res["barcode"]])
            positions = self._reservation_positions(conn)
            conn.execute("COMMIT")
            res = conn.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()
            return self.send_json({"ok": True, "reservation": self.reservation_json(res, positions)})
        except ApiError as err:
            safe_rollback(conn)
            raise
        except Exception:
            safe_rollback(conn)
            raise

    def api_loan_batch_return(self, conn, token=None):
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
        self.expire_reservations(conn)
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
            promoted = self._promote_ready(conn, returned)
            conn.execute("COMMIT")
            self._audit(conn, token, "批次還書", detail="共 {} 本：{}".format(
                len(returned), "、".join(returned[:10]) + ("…" if len(returned) > 10 else "")))
        except ApiError as err:
            safe_rollback(conn)
            raise
        except Exception:
            safe_rollback(conn)
            raise
        return self.send_json({"ok": True, "returned": returned, "total": len(returned), "promoted": promoted})

    def api_book_upsert(self, conn, barcode, token=None):
        data = self.read_json()
        title = _clean_text(data.get("title"), "書名", 200, required=True)
        asset = _clean_text(data.get("assetId", ""), "財產編號", 64)
        remarks = _clean_text(data.get("remarks") or "", "備註", 500)
        call_no = _clean_text(data.get("callNo") or data.get("call_no") or "", "索書號", 50)
        isbn = _clean_text(data.get("isbn") or data.get("ISBN") or "", "ISBN", 32)
        status = None
        raw_status = data.get("status")
        if isinstance(raw_status, str) and raw_status.strip():
            status = raw_status.strip()
            if status not in ("在館", "借出", "遺失", "修繕中", "爭議中", "報廢"):
                raise ApiError(400, "請求狀態不合法，{}".format(status))

        conn.execute("BEGIN IMMEDIATE")
        was_insert = False
        try:
            row = conn.execute(
                "SELECT * FROM books WHERE barcode = ?", (barcode,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE books SET title = ?, asset_id = ?, call_no = ?, isbn = ?, remarks = ?, updated_at = ? "
                    "WHERE barcode = ?",
                    (title, asset, call_no, isbn, remarks, now_display(), barcode),
                )
                if status:
                    conn.execute(
                        "UPDATE books SET status = ? WHERE barcode = ?",
                        (status, barcode),
                    )
            else:
                conn.execute(
                    "INSERT INTO books (barcode, title, asset_id, status, remarks, call_no, isbn, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (barcode, title, asset, status or "在館", remarks, call_no, isbn, now_display(), now_display()),
                )
                was_insert = True
            conn.execute("COMMIT")
        except Exception:
            safe_rollback(conn)
            raise
        self._audit(conn, token, "新增圖書" if was_insert else "編輯圖書",
                    target=barcode, detail=title)

        book = conn.execute(
            "SELECT * FROM books WHERE barcode = ?", (barcode,)
        ).fetchone()
        return self.send_json({"ok": True, "barcode": barcode, "book": book_json(book)})

    def api_book_action(self, conn, barcode, action, token=None):
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
        self._audit(conn, token, "報廢圖書" if action == "scrap" else "復原圖書",
                    target=barcode, detail=(row["title"] or ""))

        book = conn.execute(
            "SELECT * FROM books WHERE barcode = ?", (barcode,)
        ).fetchone()
        return self.send_json({"ok": True, "book": book_json(book)})

    def api_book_delete(self, conn, barcode, token=None):
        row = conn.execute(
            "SELECT * FROM books WHERE barcode = ?", (barcode,)
        ).fetchone()
        if not row:
            raise ApiError(404, "找不到此圖書")
        if row["status"] != "報廢":
            raise ApiError(409, "只有已報廢的圖書可以永久刪除")
        conn.execute("DELETE FROM books WHERE barcode = ?", (barcode,))
        self._audit(conn, token, "刪除圖書", target=barcode, detail=(row["title"] or ""))
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
            conditions.append("(title LIKE ? OR asset_id LIKE ? OR barcode LIKE ? OR isbn LIKE ? OR remarks LIKE ?)")
            like = "%" + keyword + "%"
            params.extend([like, like, like, like, like])
        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            "SELECT * FROM books" + where_sql + " ORDER BY barcode",
            params,
        ).fetchall()
        groups = {}
        for r in rows:
            key = (r["title"], r["asset_id"])
            if key not in groups:
                groups[key] = {"title": r["title"], "assetId": r["asset_id"], "callNo": r["call_no"] or "", "isbn": r["isbn"] or "", "copies": []}
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
                "isbn": g["isbn"],
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
            exists = conn.execute(
                "SELECT 1 FROM users WHERE class_id = ? AND name = ?",
                (row["id"], name),
            ).fetchone()
            ensure_member_user(conn, row["id"], name)
            if not exists:
                imported += 1
        self._audit(conn, token, "批次匯入成員",
                    detail="匯入 {} 筆／總數 {}".format(imported, len(raw)))
        return self.send_json({"ok": True, "imported": imported, "total": len(raw)})

    def api_member_add(self, conn, token):
        data = self.read_json()
        name = _clean_text(data.get("name"), "姓名", 50, required=True)

        raw_role = _clean_text(data.get("role") or "", "角色", 20)
        if raw_role and raw_role not in ("admin", "root", "teacher", "student"):
            raise ApiError(400, "角色不合法")

        if data.get("staff"):
            require_admin(conn, token)
            username = next_username(conn)
            email = _clean_text(data.get("email") or "", "Email", 254)
            is_admin_role = (raw_role or "teacher") in ("admin", "root")
            cursor = conn.execute(
                "INSERT INTO users (username, name, password, role, class_id, email, active, "
                "can_loan, can_member, can_book, can_config, can_report) "
                "VALUES (?, ?, ?, ?, NULL, ?, 1, ?, ?, ?, ?, ?)",
                (
                    username, name, hash_password(DEFAULT_PASSWORD), raw_role or "teacher", email,
                    1 if (is_admin_role or data.get("canLoan", True)) else 0,
                    1 if (is_admin_role or data.get("canMember")) else 0,
                    1 if (is_admin_role or data.get("canBook")) else 0,
                    1 if (is_admin_role or data.get("canConfig")) else 0,
                    1 if (is_admin_role or data.get("canReport")) else 0,
                ),
            )
            self._audit(conn, token, "新增教職員帳號", target=username,
                        detail="{}｜角色 {}".format(name, raw_role or "teacher"))
            return self.send_json({
                "ok": True,
                "memberDB": build_state(conn)["memberDB"],
                "account": {"id": cursor.lastrowid, "username": username},
            })

        class_name = _clean_text(data.get("className"), "班級", 50, required=True)
        row = conn.execute(
            "SELECT id FROM classes WHERE name = ? AND active = 1", (class_name,)
        ).fetchone()
        if not row:
            raise ApiError(404, "找不到班級：{}".format(class_name))
        member_flags = (
            1 if data.get("canLoan", True) else 0,
            1 if data.get("canMember") else 0,
            1 if data.get("canBook") else 0,
            1 if data.get("canConfig") else 0,
            1 if data.get("canReport") else 0,
        )
        user_id = ensure_member_user(conn, row["id"], name, member_flags)
        if raw_role and raw_role != "student":
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (raw_role, user_id))
        account = conn.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        self._audit(conn, token, "新增成員", target=name,
                    detail="{}班（帳號 {}）".format(class_name,
                        account["username"] if account else ""))
        account = conn.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return self.send_json({
            "ok": True,
            "memberDB": build_state(conn)["memberDB"],
            "account": {"id": user_id, "username": account["username"] if account else ""},
        })

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
            isbn = _clean_text(item.get("isbn") or item.get("ISBN") or item.get("國際書號") or "", "ISBN", 32)
            status = _clean_text(item.get("status") or "在館", "狀態", 20) or "在館"
            if not barcode or not title:
                continue
            conn.execute(
                "INSERT INTO books (barcode, title, asset_id, status, remarks, isbn, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(barcode) DO UPDATE SET title = excluded.title, asset_id = excluded.asset_id, isbn = excluded.isbn, status = excluded.status, updated_at = excluded.updated_at",
                (barcode, title, asset_id, status, "", isbn, now_display(), now_display()),
            )
            imported += 1
        self._audit(conn, token, "批次匯入圖書",
                    detail="匯入 {} 筆／總數 {}".format(imported, len(raw)))
        return self.send_json({"ok": True, "imported": imported, "total": len(raw)})

    def api_member_delete(self, conn, query, token=None):
        class_name = _clean_text(query.get("className", [""])[0], "班級", 50, required=True)
        name = _clean_text(query.get("name", [""])[0], "姓名", 50, required=True)
        # 不直接刪除帳號：改為停用，保留密碼、Email 與歷史；日後重新加入可恢復。
        ids = [
            r["id"]
            for r in conn.execute(
                "SELECT u.id FROM users u JOIN classes c ON c.id = u.class_id "
                "WHERE u.name = ? AND c.name = ?",
                (name, class_name),
            )
        ]
        for user_id in ids:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute(
            "UPDATE users SET active = 0, updated_at = datetime('now', 'localtime') "
            "WHERE id IN (SELECT u.id FROM users u JOIN classes c ON c.id = u.class_id "
            "WHERE u.name = ? AND c.name = ?)",
            (name, class_name),
        )
        self._audit(conn, token, "停用成員", target=name,
                    detail="{}班｜停用帳號 {} 個".format(class_name, len(ids)))
        return self.send_json({"ok": True, "memberDB": build_state(conn)["memberDB"]})

    def api_classes(self, conn, token=None):
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

        self._audit(conn, token, "修改班級清單",
                    detail="班級 {} 個：{}".format(len(classes), "、".join(classes[:12]) + ("…" if len(classes) > 12 else "")))
        return self.send_json({"ok": True, **build_state(conn)})

    def api_password(self, conn, token):
        data = self.read_json()
        password = data.get("password")
        if not isinstance(password, str) or len(password) < 4:
            raise ApiError(400, "密碼至少需 4 個字元")
        if len(password) > 128:
            raise ApiError(400, "密碼過長")

        session = conn.execute(
            "SELECT user_id FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if not session:
            raise ApiError(401, "請先登入")
        hashed = hash_password(password)
        if session["user_id"] is None:
            # 共用管理員：改 settings 的管理密碼
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'admin_password'",
                (hashed,),
            )
            conn.execute("DELETE FROM sessions WHERE token != ?", (token,))
        else:
            # 個別帳號：只改自己的密碼，不影響共用管理員
            conn.execute(
                "UPDATE users SET password = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                (hashed, session["user_id"]),
            )
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token != ?",
                (session["user_id"], token),
            )
        self._audit(conn, token, "修改密碼",
                    detail=("共用管理員密碼已變更" if session["user_id"] is None
                            else "個人密碼已變更"))
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

    # ------------------------------------------------------------------
    # 忘記密碼／救援
    # ------------------------------------------------------------------

    def api_recovery_info(self, conn, query):
        username = (query.get("username") or [""])[0].strip()
        target = target_email(conn, username)
        email = target[2] if target else ""
        return self.send_json({
            "hasEmail": bool(email),
            "maskedEmail": mask_email(email),
            "smtpConfigured": smtp_configured(conn),
            "localRecoveryAvailable": bool(read_recovery_code()),
        })

    def api_forgot_request(self, conn):
        ip = self.client_address[0]
        rate_limit("forgot-request", ip, 5)
        data = self.read_json()
        username = _clean_text(data.get("username") or "", "帳號", 50)
        target = target_email(conn, username)
        if not target:
            raise ApiError(400, "查無此帳號，或帳號已停用")
        target_key, _target_id, email, label = target
        if not valid_email(email):
            raise ApiError(400, "此帳號尚未設定 Email，請聯絡管理員設定，或改用本機復原碼")
        if not smtp_configured(conn):
            raise ApiError(503, "尚未設定 SMTP 寄件服務，請管理員至「系統設定 → 密碼救援」填寫，或改用本機復原碼")

        code = "{:06d}".format(secrets.randbelow(1_000_000))
        now = time.time()
        conn.execute(
            "UPDATE password_resets SET used = 1 WHERE target_key = ? AND used = 0",
            (target_key,),
        )
        cursor = conn.execute(
            "INSERT INTO password_resets "
            "(target_key, target_email, code_hash, created_at, expires_at, requester_ip) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                target_key,
                email,
                hash_password(code),
                now,
                now + RESET_CODE_TTL,
                ip,
            ),
        )
        try:
            send_recovery_email(conn, email, code, label)
        except Exception:
            conn.execute("DELETE FROM password_resets WHERE id = ?", (cursor.lastrowid,))
            raise

        log_audit(conn, "申請密碼救援", None, label or username,
                  target=username, detail="已寄出驗證碼", ip=ip)
        return self.send_json({
            "ok": True,
            "maskedEmail": mask_email(email),
            "expiresIn": RESET_CODE_TTL,
        })

    def api_forgot_verify(self, conn):
        ip = self.client_address[0]
        rate_limit("forgot-verify", ip, 10)
        data = self.read_json()
        username = _clean_text(data.get("username") or "", "帳號", 50)
        code = str(data.get("code") or "").strip()
        new_password = data.get("newPassword") or data.get("password")
        if len(code) != 6 or not code.isdigit():
            raise ApiError(400, "請輸入 6 位數驗證碼")
        if not isinstance(new_password, str) or len(new_password) < 4:
            raise ApiError(400, "新密碼至少需 4 個字元")
        if len(new_password) > 128:
            raise ApiError(400, "新密碼過長")

        target = target_email(conn, username)
        if not target:
            raise ApiError(400, "驗證碼錯誤或已失效，請重新取得")
        target_key, target_id, _email, _label = target
        now = time.time()
        row = conn.execute(
            "SELECT * FROM password_resets WHERE target_key = ? AND used = 0 "
            "ORDER BY id DESC LIMIT 1",
            (target_key,),
        ).fetchone()
        if not row or row["expires_at"] < now:
            raise ApiError(400, "驗證碼已失效，請重新取得")
        if row["attempts"] >= RESET_MAX_ATTEMPTS:
            conn.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (row["id"],))
            raise ApiError(429, "驗證碼嘗試次數過多，請重新取得")

        conn.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
        if not verify_password(code, row["code_hash"]):
            raise ApiError(400, "驗證碼錯誤")

        hashed = hash_password(new_password)
        if target_key == "admin":
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)",
                (hashed,),
            )
        else:
            conn.execute(
                "UPDATE users SET password = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                (hashed, target_id),
            )
        conn.execute("UPDATE password_resets SET used = 1 WHERE target_key = ? AND used = 0", (target_key,))
        conn.execute("DELETE FROM sessions")
        clear_rate_limit("forgot-verify", ip)
        log_audit(conn, "密碼救援重設", target_id if target_key != "admin" else None,
                  _label or username, target=username,
                  detail="密碼已重設（電子郵件驗證碼）", ip=ip)
        return self.send_json({"ok": True})

    def api_recovery_code(self, conn):
        ip = self.client_address[0]
        rate_limit("recovery-code", ip, 10)
        data = self.read_json()
        code = str(data.get("code") or "").strip()
        new_password = data.get("newPassword") or data.get("password")
        if not code:
            raise ApiError(400, "請輸入本機復原碼")
        if not isinstance(new_password, str) or len(new_password) < 4:
            raise ApiError(400, "新密碼至少需 4 個字元")
        if len(new_password) > 128:
            raise ApiError(400, "新密碼過長")
        expected = read_recovery_code()
        if not expected:
            raise ApiError(503, "本機復原碼尚未建立，請管理員重新產生")
        if not hmac.compare_digest(code, expected):
            raise ApiError(401, "復原碼錯誤")

        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)",
            (hash_password(new_password),),
        )
        conn.execute("DELETE FROM sessions")
        clear_rate_limit("recovery-code", ip)
        log_audit(conn, "本機復原碼重設", None, "共用管理員",
                  detail="以復原碼重設共用管理員密碼", ip=ip)
        return self.send_json({"ok": True})

    def api_recovery_settings_get(self, conn):
        cfg = smtp_config(conn)
        return self.send_json({
            "adminRecoveryEmail": get_setting(conn, "admin_recovery_email", ""),
            "smtp": {
                "host": cfg["host"],
                "port": cfg["port"],
                "security": cfg["security"],
                "username": cfg["username"],
                "from": cfg["from"],
                "hasPassword": bool(cfg["password"]),
            },
            "localRecoveryAvailable": bool(read_recovery_code()),
        })

    def api_recovery_settings_put(self, conn):
        data = self.read_json()
        email = _clean_text(data.get("adminRecoveryEmail") or "", "管理員救援信箱", 254)
        if email and not valid_email(email):
            raise ApiError(400, "管理員救援信箱格式錯誤")

        smtp = data.get("smtp") or {}
        if not isinstance(smtp, dict):
            raise ApiError(400, "SMTP 設定格式錯誤")
        host = _clean_text(smtp.get("host") or "", "SMTP 主機", 255)
        try:
            port = int(smtp.get("port") or 587)
        except (TypeError, ValueError):
            raise ApiError(400, "SMTP 連接埠格式錯誤")
        if port < 1 or port > 65535:
            raise ApiError(400, "SMTP 連接埠需介於 1–65535")
        security = smtp.get("security") or "starttls"
        if security not in ("starttls", "ssl", "none"):
            raise ApiError(400, "SMTP 加密方式不合法")
        smtp_user = _clean_text(smtp.get("username") or "", "SMTP 帳號", 255)
        from_addr = _clean_text(smtp.get("from") or "", "寄件者信箱", 254)
        if from_addr and not valid_email(from_addr):
            raise ApiError(400, "寄件者信箱格式錯誤")

        password = smtp.get("password")
        if isinstance(password, str) and len(password) > 512:
            raise ApiError(400, "SMTP 密碼過長")

        values = {
            "admin_recovery_email": email,
            "smtp_host": host,
            "smtp_port": str(port),
            "smtp_security": security,
            "smtp_username": smtp_user,
            "smtp_from": from_addr,
        }
        for key, value in values.items():
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

        password = smtp.get("password")
        if smtp.get("clearPassword"):
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('smtp_password', '')")
        elif isinstance(password, str) and password:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('smtp_password', ?)", (password,))

        self._audit(conn, self.cookies().get("sid"), "修改密碼救援設定",
                    target=(email or "（共用管理員）"),
                    detail="SMTP／救援信箱已更新（密碼欄位{}變更）".format("已" if smtp.get("password") or smtp.get("clearPassword") else "未"))
        return self.send_json({"ok": True})

    def api_recovery_code_regenerate(self):
        code = regenerate_recovery_code()
        conn = connect()
        try:
            log_audit(conn, "重新產生本機復原碼", None, "共用管理員",
                      detail="舊復原碼已失效", ip=self.client_address[0])
        finally:
            conn.close()
        return self.send_json({"ok": True, "code": code, "filename": "data/recovery_code.txt"})

    def api_accounts_list(self, conn):
        rows = conn.execute(
            "SELECT u.id, u.username, u.name, u.role, u.email, u.active, u.class_id, "
            "c.name AS class_name "
            "FROM users u LEFT JOIN classes c ON c.id = u.class_id ORDER BY u.id"
        ).fetchall()
        return self.send_json({
            "accounts": [
                {
                    "id": r["id"],
                    "username": r["username"],
                    "name": r["name"] or "",
                    "role": r["role"],
                    "email": r["email"] or "",
                    "active": bool(r["active"]),
                    "classId": r["class_id"],
                    "className": r["class_name"] or "",
                }
                for r in rows
            ]
        })

    def api_account_upsert(self, conn, account_id):
        data = self.read_json()
        role = data.get("role") or "teacher"
        if role not in ("admin", "root", "teacher", "student"):
            raise ApiError(400, "角色不合法")
        email = _clean_text(data.get("email") or "", "Email", 254)
        if email and not valid_email(email):
            raise ApiError(400, "Email 格式錯誤")
        password = data.get("password")
        if password is not None and (not isinstance(password, str) or len(password) < 4 or len(password) > 128):
            raise ApiError(400, "密碼需為 4–128 個字元")
        active = 1 if data.get("active", True) else 0

        if account_id is None:
            username = _clean_text(data.get("username") or "", "帳號", 50, required=True)
            name = _clean_text(data.get("name") or "", "姓名", 50)
            if not isinstance(password, str) or not password:
                raise ApiError(400, "新增帳號需設定密碼")
            exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if exists:
                raise ApiError(409, "帳號已存在")
            cursor = conn.execute(
                "INSERT INTO users (username, name, password, role, email, active) VALUES (?, ?, ?, ?, ?, ?)",
                (username, name, hash_password(password), role, email, active),
            )
            return self.send_json({"ok": True, "id": cursor.lastrowid})

        row = conn.execute("SELECT id, name FROM users WHERE id = ?", (account_id,)).fetchone()
        if not row:
            raise ApiError(404, "找不到帳號")
        if "name" in data:
            name = _clean_text(data.get("name") or "", "姓名", 50)
        else:
            name = row["name"] or ""
        conn.execute(
            "UPDATE users SET name = ?, role = ?, email = ?, active = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
            (name, role, email, active, account_id),
        )
        if isinstance(password, str) and password:
            conn.execute(
                "UPDATE users SET password = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                (hash_password(password), account_id),
            )
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (account_id,))
        if not active:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (account_id,))
        return self.send_json({"ok": True, "id": account_id})

    def api_account_reset_password(self, conn, account_id, token=None):
        data = self.read_json()
        password = data.get("password")
        if not isinstance(password, str) or len(password) < 4 or len(password) > 128:
            raise ApiError(400, "密碼需為 4–128 個字元")
        row = conn.execute("SELECT id, username FROM users WHERE id = ?", (account_id,)).fetchone()
        if not row:
            raise ApiError(404, "找不到帳號")
        conn.execute(
            "UPDATE users SET password = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
            (hash_password(password), account_id),
        )
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (account_id,))
        self._audit(conn, token, "重設帳號密碼", target=row["username"],
                    detail="密碼已重設，該帳號所有裝置已登出")
        return self.send_json({"ok": True})

    def api_member_accounts_list(self, conn):
        rows = conn.execute(
            "SELECT u.id, u.username, u.name, u.role, u.email, u.active, u.class_id, "
            "u.can_loan, u.can_member, u.can_book, u.can_config, u.can_report, "
            "CASE WHEN u.password <> '' THEN 1 ELSE 0 END AS has_password, "
            "c.name AS class_name "
            "FROM users u LEFT JOIN classes c ON c.id = u.class_id "
            "WHERE u.active = 1 "
            "ORDER BY CASE WHEN u.class_id IS NULL THEN 1 ELSE 0 END, "
            "c.sort_order, c.id, u.id"
        ).fetchall()
        return self.send_json({
            "accounts": [
                {
                    "id": r["id"],
                    "username": r["username"],
                    "name": r["name"] or "",
                    "role": r["role"],
                    "email": r["email"] or "",
                    "classId": r["class_id"],
                    "className": r["class_name"] or "",
                    "hasPassword": bool(r["has_password"]),
                    "canLoan": bool(r["can_loan"]),
                    "canMember": bool(r["can_member"]),
                    "canBook": bool(r["can_book"]),
                    "canConfig": bool(r["can_config"]),
                    "canReport": bool(r["can_report"]),
                }
                for r in rows
            ]
        })

    def _member_account_row(self, conn, account_id):
        row = conn.execute("SELECT * FROM users WHERE id = ?", (account_id,)).fetchone()
        if not row:
            raise ApiError(404, "找不到成員帳號")
        return row

    def _require_account_manager(self, conn, token, row):
        """班級成員由教職員管理；未分班教職員與管理員帳號僅限系統管理員。"""
        if row["class_id"] is None or (row["role"] or "") in ("admin", "root"):
            require_admin(conn, token)

    def api_member_account_update(self, conn, account_id, token):
        row = self._member_account_row(conn, account_id)
        self._require_account_manager(conn, token, row)
        data = self.read_json()

        username = row["username"]
        if "username" in data:
            username = _clean_text(data.get("username") or "", "帳號", 50, required=True)
            duplicate = conn.execute(
                "SELECT id FROM users WHERE username = ? AND id <> ?",
                (username, account_id),
            ).fetchone()
            if duplicate:
                raise ApiError(409, "帳號已存在")

        name = row["name"] or ""
        if "name" in data:
            name = _clean_text(data.get("name") or "", "姓名", 50, required=True)
            if row["class_id"] is not None:
                duplicate_name = conn.execute(
                    "SELECT id FROM users WHERE class_id = ? AND name = ? AND active = 1 AND id <> ?",
                    (row["class_id"], name, account_id),
                ).fetchone()
                if duplicate_name:
                    raise ApiError(409, "同班級已有同名成員")

        email = row["email"] or ""
        if "email" in data:
            email = _clean_text(data.get("email") or "", "Email", 254)
            if email and not valid_email(email):
                raise ApiError(400, "Email 格式錯誤")

        new_class_id = row["class_id"]
        if "classId" in data or "className" in data:
            raw_class = data.get("classId")
            if raw_class is None and "className" in data:
                raw_name = _clean_text(data.get("className") or "", "班級", 50)
                raw_class = "__staff__" if not raw_name else raw_name
            if isinstance(raw_class, str) and raw_class.strip() == "__staff__":
                new_class_id = None
            elif isinstance(raw_class, int):
                new_class_id = raw_class
            else:
                new_name = _clean_text(str(raw_class or ""), "班級", 50)
                if new_name:
                    class_row = conn.execute("SELECT id FROM classes WHERE name = ?", (new_name,)).fetchone()
                    if not class_row:
                        raise ApiError(400, "找不到班級：{}".format(new_name))
                    new_class_id = class_row["id"]
                else:
                    new_class_id = None
            new_class_id = new_class_id if new_class_id is not None else None

        new_role = row["role"] or "teacher"
        if "role" in data:
            new_role = _clean_text(data.get("role") or "", "角色", 20)
            if new_role not in ("admin", "root", "teacher", "student"):
                raise ApiError(400, "角色不合法")

        password = data.get("password")
        if password is not None and (
            not isinstance(password, str) or len(password) < 4 or len(password) > 128
        ):
            raise ApiError(400, "密碼需為 4–128 個字元")

        can_flags = [
            1 if data.get("canLoan", True) else 0,
            1 if data.get("canMember", False) else 0,
            1 if data.get("canBook", False) else 0,
            1 if data.get("canConfig", False) else 0,
            1 if data.get("canReport", False) else 0,
        ]
        conn.execute(
            "UPDATE users SET class_id = ?, role = ?, name = ?, email = ?, "
            "can_loan = ?, can_member = ?, can_book = ?, can_config = ?, can_report = ?, "
            "updated_at = datetime('now', 'localtime') WHERE id = ?",
            tuple([
                new_class_id, new_role, name, email, *can_flags, account_id,
            ]),
        )
        if isinstance(password, str) and password:
            conn.execute(
                "UPDATE users SET password = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                (hash_password(password), account_id),
            )
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (account_id,))
        self._audit(conn, token, "修改帳號", target=username,
                    detail="姓名「{}」｜角色 {}｜權限 借還書:{} 成員:{} 圖書:{} 設定:{} 報表:{}".format(
                        name, new_role,
                        "✓" if can_flags[0] else "✗", "✓" if can_flags[1] else "✗",
                        "✓" if can_flags[2] else "✗", "✓" if can_flags[3] else "✗",
                        "✓" if can_flags[4] else "✗") + ("｜密碼已同改" if password else ""))
        return self.send_json({"ok": True, "id": account_id})

    def api_member_account_reset_password(self, conn, account_id, token):
        row = self._member_account_row(conn, account_id)
        self._require_account_manager(conn, token, row)
        return self.api_account_reset_password(conn, account_id, token)

    def api_member_account_delete(self, conn, account_id, token):
        row = self._member_account_row(conn, account_id)
        self._require_account_manager(conn, token, row)
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (account_id,))
        conn.execute(
            "UPDATE users SET active = 0, updated_at = datetime('now', 'localtime') WHERE id = ?",
            (account_id,),
        )
        self._audit(conn, token, "停用帳號", target=row["username"],
                    detail="帳號 {}（{}）已停用".format(row["username"], row["name"] or ""))
        return self.send_json({"ok": True, "memberDB": build_state(conn)["memberDB"]})

    def api_import(self, conn, token):
        data = self.read_json(limit=MAX_BODY)
        payload = data.get("data") if isinstance(data.get("data"), dict) else data
        classes, member_db, books, logs = validate_import(payload)

        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM books")
            conn.execute("DELETE FROM loan_logs")

            # 不刪除 users / classes，避免遺失帳號密碼與 Email。
            # 先全部停用，再依匯入資料恢復；未出現在匯入資料的成員會保持停用。
            conn.execute("UPDATE users SET active = 0 WHERE class_id IS NOT NULL")
            conn.execute("UPDATE classes SET active = 0")

            active = set(classes)
            for index, cls in enumerate(classes):
                row = conn.execute("SELECT id FROM classes WHERE name = ?", (cls,)).fetchone()
                if row:
                    conn.execute(
                        "UPDATE classes SET sort_order = ?, active = 1 WHERE id = ?",
                        (index, row["id"]),
                    )
                else:
                    conn.execute(
                        "INSERT INTO classes (name, sort_order, active) VALUES (?, ?, 1)",
                        (cls, index),
                    )
            # 只有成員、但不在班級清單的班級，以停用方式保留
            for cls in member_db:
                if cls in active:
                    continue
                row = conn.execute("SELECT id FROM classes WHERE name = ?", (cls,)).fetchone()
                if row:
                    conn.execute("UPDATE classes SET active = 0 WHERE id = ?", (row["id"],))
                else:
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
                    ensure_member_user(conn, class_id, name)

            for barcode, book in books.items():
                conn.execute(
                    "INSERT INTO books (barcode, title, asset_id, isbn, status, loaned_to, "
                    "borrow_count, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        barcode, book["title"], book["asset_id"], book["isbn"], book["status"],
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

        self._audit(conn, token, "匯入備份", detail="還原書籍、成員與借閱紀錄")
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
    print("  救援復原碼：{}（請妥善保管，勿公開）".format(recovery_code_path()))
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
