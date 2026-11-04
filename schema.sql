-- 幼兒園圖書資訊管理系統 — SQLite 資料庫結構
--
-- 設計原則：
--   1. 以「條碼」作為館藏主鍵，符合條碼槍掃描流程。
--   2. 班級、成員各自成表；成員姓名只要求在「同班」內不重複。
--   3. 借閱狀態存在 books，借還歷史存在 loan_logs（歷史不隨刪書消失）。
--   4. 所有時間以伺服器本機時間儲存，與原本系統顯示格式一致。
--   5. 密碼只存 PBKDF2 雜湊，不存明碼。

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- 系統設定（鍵值對）
-- admin_password : pbkdf2_sha256$迭代次數$salt$hash
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL
);

-- 班級。active = 0 表示已從班級清單移除，但成員資料保留，重新加入即可恢復。
CREATE TABLE IF NOT EXISTS classes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    active     INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

-- 班級成員與系統帳號整併於 users 表（class_id 有值＝班級成員）。
-- 舊版 members 表已由 server.py 的遷移程式併入 users 並移除。

-- 館藏。barcode 為條碼槍讀到的值，也是主鍵。
-- status：在館 / 借出 / 遺失 / 修繕中 / 爭議中 / 報廢
--   遺失、修繕中、爭議中：設定為無法借出（客製化需求清單 v2.1 4.1）。
--   修繕中：老師進行膠帶修補，暫時下架，修補完成後恢復為「在館」。
--   爭議中：既非在館，也無法證實遺失，暫停計算逾期。
--   遺失為「報廢」前的緩衝狀態；買回則於備註註銷。
-- loaned_to / loan_class 只在借出時有值，歸還後清空。
CREATE TABLE IF NOT EXISTS books (
    barcode      TEXT    PRIMARY KEY,
    title        TEXT    NOT NULL,
    asset_id     TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL DEFAULT '在館'
                 CHECK (status IN ('在館', '借出', '遺失', '修繕中', '爭議中', '報廢')),
    loaned_to    TEXT,
    loan_class   TEXT,
    borrow_count INTEGER NOT NULL DEFAULT 0,
    remarks      TEXT    NOT NULL DEFAULT '',
    due_at       TEXT,
    call_no      TEXT    NOT NULL DEFAULT '',   -- 索書號：[主題分類代碼]-[書名首字注音]，如 D-ㄏ
    category     TEXT    NOT NULL DEFAULT '',   -- 主題分類代碼（A-E, S），供索書號自動產生與排架
    isbn         TEXT    NOT NULL DEFAULT '',
    publisher    TEXT    NOT NULL DEFAULT '',   -- 出版社
    price        INTEGER NOT NULL DEFAULT 0,    -- 單價（新台幣元）
    quantity     INTEGER NOT NULL DEFAULT 1,    -- 數量（固定 1）
    source       TEXT    NOT NULL DEFAULT '',   -- 來源：自購／軍購／捐贈／英補／署補
    purchase_date TEXT   NOT NULL DEFAULT '',   -- 書籍購入日期（民國年格式 115/05/16）
    keeper       TEXT    NOT NULL DEFAULT '',   -- 保管人
    confirm_note TEXT    NOT NULL DEFAULT '',   -- 確認（自由文字）
    inventory_date TEXT   NOT NULL DEFAULT '',  -- 盤點日期（民國年格式）
    scrap_date   TEXT    NOT NULL DEFAULT '',   -- 報廢日期（民國年格式）
    created_at   TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 主題分類：供索書號自動產生與書架排架（規格 v2.1 4.5）
CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL DEFAULT '',   -- 分類名稱，如 語文與故事
    code        TEXT    NOT NULL DEFAULT '',   -- 系統分類代碼，大寫英文字母，如 A/B/C/D/E/S
    color       TEXT    NOT NULL DEFAULT '',   -- 實體對應顏色，如 黃色／紅色／藍色／綠色／紫色／橘色
    sort_order  INTEGER NOT NULL DEFAULT 0,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_books_status ON books (status);
CREATE INDEX IF NOT EXISTS idx_books_loaned_to ON books (loaned_to);

-- 借還歷史。刻意不設 FOREIGN KEY：永久刪除館藏後，歷史仍須保留。
CREATE TABLE IF NOT EXISTS loan_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT    NOT NULL,              -- 顯示用：2026/10/20 下午 04:45:00
    created_at  TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    barcode     TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    asset_id    TEXT    NOT NULL DEFAULT '',
    class_name  TEXT    NOT NULL,
    user_name   TEXT    NOT NULL,
    action      TEXT    NOT NULL CHECK (action IN ('借書', '還書')),
    -- 還書時當下是否逾期（1＝逾期、0＝期限內），用於「逾期已還紀錄清冊」
    was_overdue INTEGER,
    -- 還書時的應還日期快照（僅還書紀錄有值）
    due_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_loan_logs_created ON loan_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_loan_logs_barcode ON loan_logs (barcode);

-- 預約。成員在書被借走後可預約，同一成員日後借到該書時自動履約。
CREATE TABLE IF NOT EXISTS reservations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    expires_at TEXT,
    barcode     TEXT NOT NULL,
    title       TEXT NOT NULL,
    asset_id    TEXT NOT NULL DEFAULT '',
    class_name  TEXT NOT NULL,
    user_name   TEXT NOT NULL,
    member_type TEXT NOT NULL DEFAULT 'student',
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'cancelled', 'fulfilled', 'ready', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_reservations_barcode ON reservations (barcode, status);
CREATE INDEX IF NOT EXISTS idx_reservations_user ON reservations (user_name, status);

-- 登入工作階段。token 為隨機字串，存於 HttpOnly Cookie。
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 系統帳號，同時也是班級成員名單（單一資料表）。
-- class_id 有值＝班級成員（學生）；class_id 為 NULL＝教職員／系統管理員。
-- name 為顯示用姓名；email 供「忘記密碼」寄送驗證碼使用，可留空。
-- can_* 為功能權限旗標：借還書／班級成員／圖書管理／系統設定／報表列印。
-- admin/root 角色與共用管理員不受欄位限制，一律全權限。
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL DEFAULT '',
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL DEFAULT 'teacher',
    class_id   INTEGER REFERENCES classes(id) ON DELETE SET NULL,
    email      TEXT    NOT NULL DEFAULT '',
    barcode    TEXT    NOT NULL DEFAULT '',   -- 成員條碼：學生 SA+班級+號碼（如 SA01）、老師 T+員工編號（如 T001）
    active     INTEGER NOT NULL DEFAULT 1,
    can_loan   INTEGER NOT NULL DEFAULT 0,
    can_member INTEGER NOT NULL DEFAULT 0,
    can_book   INTEGER NOT NULL DEFAULT 0,
    can_config INTEGER NOT NULL DEFAULT 0,
    can_report INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_users_class_name ON users (class_id, name);

-- 忘記密碼驗證碼。只存雜湊，不存明碼；每次請求覆蓋舊碼。
-- target_key：'admin'（共用管理員）或 'user:<users.id>'
CREATE TABLE IF NOT EXISTS password_resets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_key   TEXT    NOT NULL,
    target_email TEXT    NOT NULL DEFAULT '',
    code_hash    TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    expires_at   REAL    NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    used         INTEGER NOT NULL DEFAULT 0,
    requester_ip TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_password_resets_target
    ON password_resets (target_key, used, expires_at);

-- 稽核紀錄：僅記錄管理／設定／帳號操作，不記借還書（借還書有 loan_logs）。
-- 只增不刪、不改，供日後稽核。actor_user_id 為 NULL 代表共用管理員。
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at    TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    actor_user_id  INTEGER,
    actor_name       TEXT NOT NULL DEFAULT '',
    action           TEXT NOT NULL,
    target           TEXT NOT NULL DEFAULT '',
    detail           TEXT NOT NULL DEFAULT '',
    ip               TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_occurred ON audit_log (occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action   ON audit_log (action);
