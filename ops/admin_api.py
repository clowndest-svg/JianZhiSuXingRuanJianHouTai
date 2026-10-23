"""轻塑后台 · 运维 API

只装"做错就救不回来"的那几件事：注销、封号、重置口令、撤销会话、抬强更门、触发备份。
低风险的字段编辑留给 Directus 数据控制台，别在这里重复一套。

三条不可让步的规矩（对应 docs/04 §3.1）：
  1. 高危动作的确认是**服务端比对**，不是浏览器弹窗；
  2. 强更门只许往上抬；
  3. 每个动作都往 admin_audit 落一行，**失败也落**。
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import logging
import os
import ipaddress
import socket
import smtplib
import ssl
import tempfile
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

APP_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("QINGSU_DB", "/opt/qingsu/data/qingsu.db")
UPLOAD_DIR = os.environ.get("QINGSU_UPLOAD_DIR", "/opt/qingsu/uploads")
MIN_BUILD_FILE = os.environ.get("QINGSU_MIN_BUILD_FILE", "/opt/qingsu/data/min_build")
WEB_DIR = os.environ.get("QINGSU_WEB_DIR", "/opt/qingsu/web")
BACKUP_SCRIPT = os.environ.get("QINGSU_BACKUP_SCRIPT", "/opt/qingsu/backup.py")
BACKUP_DIR = os.environ.get("QINGSU_BACKUP_DIR", "/opt/qingsu/backups/scheduled")
APP_API = os.environ.get("QINGSU_LOCAL_API", "http://172.17.0.1:8000")
SECRET_FILE = os.environ.get("QINGSU_ADMIN_SECRETS", "/opt/qingsu/admin/console.json")
CONSOLE_HTML = APP_DIR / "console.html"
CONTAINER_NAME = os.environ.get("QINGSU_CONSOLE_CONTAINER", "qingsu-console")
# 服务器上跑的是 python3；Windows 上 python3 是商店别名（会静默返回 49），本地测试用 sys.executable
PYTHON_BIN = os.environ.get("QINGSU_PYTHON_BIN", "python3")
MAIL_CONFIG = os.environ.get('QINGSU_MAIL_CONFIG', '/opt/qingsu/mail.json')
MAIL_CHECK = os.environ.get('QINGSU_MAIL_CHECK', '/opt/qingsu/admin/mail-check.json')
MONITOR_FILE = os.environ.get('QINGSU_MONITOR_FILE', '/opt/qingsu/monitor/status.json')
SESSION_TTL = 8 * 3600
SESSION_IDLE_TTL = 2 * 3600
SESSION_TOUCH_INTERVAL = 60
LOGIN_MAX_ATTEMPTS = 8
LOGIN_LOCK_SEC = 900

log = logging.getLogger("qingsu.ops")

# 敏感列：界面、导出、审计里的 before/after 都不许带出去（docs/02 §3）
SENSITIVE = {
    ("users", "password_hash"), ("users", "pw_salt"), ("users", "token"),
    ("users", "token_hash"), ("users", "share_secret"),
    ("sessions", "token_hash"),
    ("email_codes", "code_hash"), ("email_codes", "email_hash"),
    ("profiles", "loc_lat"), ("profiles", "loc_lng"),
    ("ai_memory", "mem_value"), ("private_ai_answers", "answer"), ("kb_entries", "answer"),
    ("body_cycles", "photo_url"), ("media_uploads", "name"), ("posts", "images"),
    ('push_subscriptions', 'endpoint'), ('push_subscriptions', 'keys_json'),
    ('push_subscriptions', 'session_hash'), ('shared_goals', 'invite_hash'),
}


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def read_images(raw) -> list:
    """posts.images 存的是 JSON 数组；坏数据当空处理（只用于判断文件有没有被引用）。"""
    try:
        data = json.loads(raw or "[]")
    except Exception:
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def db(readonly: bool = False) -> sqlite3.Connection:
    """只读连接走 URI，写连接走普通路径。
    URI 里的 Windows 反斜杠会被 sqlite 当成文件名的一部分，所以必须换成正斜杠；
    把 ?mode=ro 拼进普通路径同样打不开——这两条都是踩过才知道的。"""
    if readonly:
        conn = sqlite3.connect("file:%s?mode=ro" % Path(DB_PATH).as_posix(), uri=True, timeout=5)
    else:
        conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute("PRAGMA table_info(%s)" % table).fetchall()]


READ_FIELDS = {'ai_memory': ('user_id', 'mem_key', 'updated_at'),
 'body_cycles': ('id',
                 'user_id',
                 'cycle_num',
                 'cycle_name',
                 'weight_jin',
                 'waist_cm',
                 'tone_score',
                 'ai_report',
                 'created_at'),
 'checklist_state': ('user_id', 'log_date', 'state_json', 'updated_at'),
 'cheers': ('id', 'user_id', 'kind', 'sender_hash', 'cheer_date', 'created_at'),
 'comment_likes': ('comment_id', 'user_id', 'created_at'),
 'comments': ('id',
              'post_id',
              'user_id',
              'reply_to',
              'body',
              'region',
              'request_id',
              'status',
              'created_at',
              'images',
              'like_count'),
 'community_profile': ('user_id',
                       'bio',
                       'region',
                       'region_seen_at',
                       'discoverable',
                       'updated_at',
                       'bubble_theme'),
 'content_reports': ('id',
                     'target_kind',
                     'target_id',
                     'reporter',
                     'reason',
                     'status',
                     'handled_at',
                     'handled_note',
                     'created_at'),
 'conversations': ('conv_key', 'a_id', 'b_id', 'last_body', 'last_at', 'last_from', 'created_at'),
 'daily_metrics': ('user_id', 'log_date', 'metrics_json', 'origin'),
 'daily_modes': ('user_id', 'log_date', 'mode'),
 'daily_reviews': ('user_id', 'log_date', 'complete'),
 'email_codes': ('id', 'purpose', 'expires_at', 'attempts', 'created_at'),
 'feedback': ('id',
              'user_id',
              'kind',
              'body',
              'page',
              'app_build',
              'contact',
              'status',
              'reply',
              'created_at',
              'replied_at'),
 'follows': ('follower_id', 'followee_id', 'created_at'),
 'food_logs': ('id',
               'user_id',
               'log_date',
               'slot',
               'food_name',
               'cal',
               'protein_g',
               'carbs_g',
               'fat_g',
               'time_str',
               'created_at',
               'source',
               'estimate_reason'),
 'kb_entries': ('qkey', 'sources', 'fetched_at', 'hits'),
 'media_uploads': ('user_id', 'created_at', 'kind', 'mime', 'duration', 'metadata'),
 'mentions': ('id', 'post_id', 'comment_id', 'user_id', 'actor_id', 'created_at'),
 'messages': ('id',
              'conv_key',
              'from_id',
              'to_id',
              'body',
              'request_id',
              'created_at',
              'read_at',
              'recalled_at',
              'kind',
              'media_name',
              'media_mime',
              'media_size',
              'media_w',
              'media_h',
              'media_dur',
              'media_meta',
              'asr_text',
              'quote_id',
              'quote_name',
              'quote_kind',
              'quote_snippet'),
 'notifications': ('id',
                   'user_id',
                   'kind',
                   'actor_id',
                   'post_id',
                   'comment_id',
                   'body_text',
                   'dedup',
                   'created_at',
                   'read_at'),
 'post_favorites': ('post_id', 'user_id', 'created_at'),
 'post_likes': ('post_id', 'user_id', 'created_at'),
 'posts': ('id',
           'user_id',
           'body',
           'like_count',
           'comment_count',
           'region',
           'request_id',
           'status',
           'created_at',
           'edited_at',
           'title'),
 'private_ai_answers': ('user_id', 'question', 'updated_at'),
 'profiles': ('user_id',
              'gender',
              'age',
              'height',
              'weight_jin',
              'target_weight_jin',
              'goal_type',
              'dining_mode',
              'scene',
              'updated_at',
              'day_mode',
              'cycle_started_at',
              'email',
              'email_verified_at',
              'avatar_url',
              'city',
              'city_source',
              'avoid_tags',
              'loc_updated_at'),
 'push_subscriptions': ('user_id', 'last_notice', 'last_message', 'failures', 'updated_at'),
 'record_changes': ('id', 'user_id', 'kind', 'record_id', 'previous_json', 'operation', 'created_at'),
 'request_receipts': ('user_id', 'request_key', 'kind', 'created_at'),
 'sessions': ('user_id', 'expires_at'),
 'share_settings': ('user_id', 'enabled', 'expires_at', 'scope'),
 'shared_goal_members': ('goal_id', 'user_id'),
 'shared_goals': ('id', 'owner_id', 'title', 'kind', 'target', 'start_date', 'end_date'),
 'takeout_events': ('id', 'user_id', 'event_type', 'cal_avoided', 'dish_name', 'log_date', 'created_at'),
 'user_blocks': ('blocker', 'blocked', 'created_at'),
 'user_cities': ('user_id', 'city', 'first_seen', 'last_seen', 'hits'),
 'users': ('id', 'username', 'nickname', 'created_at', 'banned_at', 'ban_reason', 'public_id'),
 'water_logs': ('user_id', 'log_date', 'cups_count', 'updated_at'),
 'weight_logs': ('id', 'user_id', 'log_date', 'weight_jin', 'waist_cm', 'created_at'),
 'workout_logs': ('id', 'user_id', 'log_date', 'duration_minutes', 'cal_burned', 'plan_name', 'created_at')}


def safe_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """Explicit reviewed fields: unknown tables and columns are denied."""
    return [c for c in READ_FIELDS.get(table, ()) if c in columns(conn, table) and (table, c) not in SENSITIVE]



def user_refs(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """所有指向 users 的 (表, 列)。列名不能写死：社区那批表里
    follows/messages/user_blocks 用的都不是 user_id，漏一张就是留孤儿行。"""
    out = []
    names = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        " ORDER BY name").fetchall()]
    for table in names:
        cols = set(columns(conn, table))
        fks = {fk[3] for fk in conn.execute("PRAGMA foreign_key_list(%s)" % table).fetchall()
               if fk[2] == "users"}
        wanted = fks | {c for c in cols if c in (
            "user_id", "follower_id", "followee_id", "from_id", "to_id", "blocker", "blocked",
            "reporter", "actor_id", "a_id", "b_id", "last_from")}
        out += [(table, c) for c in sorted(wanted)]
    return out


# ---------------------------------------------------------------- 审计

AUDIT_SQL = """CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL, action TEXT NOT NULL,
    target_kind TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '',
    before_json TEXT NOT NULL DEFAULT '', after_json TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)"""


def audit(actor: str, action: str, target_kind: str = "", target_id: str = "",
          before=None, after=None, note: str = "") -> None:
    """留痕。失败也要留——否则排查时只看到"什么都没发生"。
    审计自己写不进去必须冒出来：吞掉就等于这个动作没发生过。"""
    conn = db()
    try:
        # 建表放在写之前：进程可能一条请求都还没跑完就有人翻审计，
        # 而且 TestClient 之类不一定触发 startup 事件——不能指望启动钩子替我兜底。
        conn.execute(AUDIT_SQL)
        conn.execute("INSERT INTO admin_audit"
                     "(actor,action,target_kind,target_id,before_json,after_json,note,created_at)"
                     " VALUES (?,?,?,?,?,?,?,?)",
                     (actor, action, target_kind, str(target_id),
                      json.dumps(before, ensure_ascii=False, default=str) if before is not None else "",
                      json.dumps(after, ensure_ascii=False, default=str) if after is not None else "",
                      str(note)[:400], now_iso()))
        conn.commit()
    finally:
        conn.close()


def audit_in(conn: sqlite3.Connection, actor: str, action: str,
             target_kind: str = "", target_id: str = "",
             before=None, after=None, note: str = "") -> None:
    """Write an audit row in the caller's transaction for moderation workflows."""
    conn.execute(AUDIT_SQL)
    conn.execute("INSERT INTO admin_audit"
                 "(actor,action,target_kind,target_id,before_json,after_json,note,created_at)"
                 " VALUES (?,?,?,?,?,?,?,?)",
                 (actor, action, target_kind, str(target_id),
                  json.dumps(before, ensure_ascii=False, default=str) if before is not None else "",
                  json.dumps(after, ensure_ascii=False, default=str) if after is not None else "",
                  str(note)[:400], now_iso()))


# ---------------------------------------------------------------- 口令


def make_pw(pw: str) -> tuple[str, str]:
    """与主应用一致：scrypt + 每用户随机盐。参数照 server.py:522，
    由 tests/test_ops_api.py 拿**主应用自己的 verify_pw** 验一次，不靠"看起来一样"。"""
    salt = secrets.token_hex(16)
    return salt, hashlib.scrypt(pw.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32).hex()


def gen_otp_password() -> str:
    """一次性口令要能被人手敲进手机，所以不用容易混的字符。"""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    body = "".join(secrets.choice(alphabet) for _ in range(10))
    return "%s-%s" % (body[:5], body[5:])


# ---------------------------------------------------------------- 鉴权

_secrets_cache: dict[str, str] = {}
_attempts: dict[str, tuple[int, float]] = {}


def load_secrets() -> tuple[str, str]:
    if "token" in _secrets_cache:
        return _secrets_cache["token"], _secrets_cache["cookie"]
    token = os.environ.get("OPS_TOKEN")
    cookie = os.environ.get("OPS_COOKIE_SECRET")
    if not token:
        data = json.loads(Path(SECRET_FILE).read_text(encoding="utf-8"))
        token = str(data["ops_token"])
        cookie = str(data.get("cookie_secret") or token)
    _secrets_cache.update(token=token, cookie=cookie)
    return token, cookie


def _sign(payload: str) -> str:
    _, cookie = load_secrets()
    return hmac.new(cookie.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]


ADMIN_SESSION_SQL = ("CREATE TABLE IF NOT EXISTS ops_sessions ("
                     "token_hash TEXT PRIMARY KEY, actor TEXT NOT NULL, created_at INTEGER NOT NULL,"
                     "last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,"
                     "absolute_expires_at INTEGER NOT NULL, credential_fp TEXT NOT NULL DEFAULT '')")


def ensure_ops_schema(conn: sqlite3.Connection) -> None:
    """后台自己的两张表：会话与媒体清理队列。

    列不能只靠 CREATE TABLE 保证——老库里已经有一张三列的 ops_sessions，
    CREATE IF NOT EXISTS 会静默跳过，新列得靠 ALTER 补，否则读会话时才发现没这列。
    """
    conn.execute(ADMIN_SESSION_SQL)
    have = {r[1] for r in conn.execute("PRAGMA table_info(ops_sessions)").fetchall()}
    for column, ddl in (("created_at", "INTEGER NOT NULL DEFAULT 0"),
                        ("last_seen_at", "INTEGER NOT NULL DEFAULT 0"),
                        ("absolute_expires_at", "INTEGER NOT NULL DEFAULT 0"),
                        ("credential_fp", "TEXT NOT NULL DEFAULT ''")):
        if column not in have:
            conn.execute("ALTER TABLE ops_sessions ADD COLUMN %s %s" % (column, ddl))


def credential_fp(token: str) -> str:
    """凭据指纹：轮换或停用某个命名账号后，它名下已签发的会话当场作废。

    只存指纹不存口令——审计库里出现一把能换登录态的明文口令，等于把口令抄在便签上。
    """
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()[:12]


def operator_tokens() -> dict[str, str]:
    """命名操作者：{名字: 口令}。名字直接进审计，"console" 这种共用身份查不出是谁。"""
    token, _ = load_secrets()
    named = os.environ.get("OPS_OPERATORS_JSON")
    if named:
        try:
            data = json.loads(named)
        except Exception:
            data = None
        if isinstance(data, dict) and data:
            return {str(k): str(v) for k, v in data.items() if v}
    try:
        raw = json.loads(Path(SECRET_FILE).read_text(encoding="utf-8")).get("operators")
    except Exception:
        raw = None
    if isinstance(raw, dict) and raw:
        return {str(k): str(v) for k, v in raw.items() if v}
    return {"console": token}


def make_session(actor: str) -> str:
    raw = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = db()
    try:
        ensure_ops_schema(conn)
        conn.execute("DELETE FROM ops_sessions WHERE absolute_expires_at<=? OR last_seen_at<=?",
                     (now, now - SESSION_IDLE_TTL))
        conn.execute("INSERT INTO ops_sessions"
                     "(token_hash,actor,created_at,last_seen_at,expires_at,absolute_expires_at,credential_fp)"
                     " VALUES (?,?,?,?,?,?,?)",
                     (hashlib.sha256(raw.encode()).hexdigest(), actor, now, now,
                      now + SESSION_TTL, now + SESSION_TTL,
                      credential_fp(operator_tokens().get(actor, ""))))
        conn.commit()
    finally:
        conn.close()
    return raw


def read_session(raw: str) -> str | None:
    if not raw:
        return None
    now = int(time.time())
    conn = db()
    try:
        ensure_ops_schema(conn)
        row = conn.execute("SELECT * FROM ops_sessions WHERE token_hash=?",
                           (hashlib.sha256(raw.encode()).hexdigest(),)).fetchone()
        if not row:
            return None
        if row["expires_at"] <= now or row["absolute_expires_at"] <= now:
            conn.execute("DELETE FROM ops_sessions WHERE token_hash=?", (row["token_hash"],))
            conn.commit()
            return None
        if row["last_seen_at"] + SESSION_IDLE_TTL <= now:
            conn.execute("DELETE FROM ops_sessions WHERE token_hash=?", (row["token_hash"],))
            conn.commit()
            return None
        current = operator_tokens().get(row["actor"])
        if current is None or credential_fp(current) != row["credential_fp"]:
            # 口令换过、或这个命名账号已经删掉：它名下的会话一律不认
            conn.execute("DELETE FROM ops_sessions WHERE token_hash=?", (row["token_hash"],))
            conn.commit()
            return None
        if now - row["last_seen_at"] >= SESSION_TOUCH_INTERVAL:
            conn.execute("UPDATE ops_sessions SET last_seen_at=? WHERE token_hash=?",
                         (now, row["token_hash"]))
            conn.commit()
        return row["actor"]
    finally:
        conn.close()


def revoke_actor_sessions(actor: str) -> int:
    conn = db()
    try:
        ensure_ops_schema(conn)
        n = conn.execute("DELETE FROM ops_sessions WHERE actor=?", (actor,)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def actor_of(request: Request,
             x_qingsu_token: str | None = Header(None),
             authorization: str | None = Header(None)) -> str:
    """应用层的身份（L3）。注意令牌走 X-Qingsu-Token 而不是 Authorization: Bearer：
    Authorization 这一格已经被 L2 的 Basic 占了，两个方案不能共用同一个头。"""
    supplied = (x_qingsu_token or "").strip()
    if not supplied and authorization and authorization.startswith("Token "):
        supplied = authorization[6:].strip()
    if supplied:
        for name, secret in operator_tokens().items():
            if hmac.compare_digest(supplied, secret):
                # 前缀 script: 是为了让审计分得清"人从界面点的"和"脚本直接调的"，
                # 同一把凭据走两条路，事后追查不该看不出区别。
                return "script:" + name
    session = read_session(request.cookies.get("qops", ""))
    if session:
        return session
    raise HTTPException(status_code=401, detail="后台未登录或会话已过期")


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def basic_gate() -> tuple[str, str]:
    """第二道闸（L2）。放这里而不是放 nginx：qingsu-tls 只把 default.conf 一个文件
    挂进容器，nginx 的 htpasswd 就必须落在容器的可写层里——容器一重建就没了，
    最坏形状是"nginx 起不来，整站下线"。这道闸放在应用里既能常数时间比对，
    又能被 tests/test_ops_api.py 直接测到。"""
    user = os.environ.get("OPS_BASIC_USER")
    password = os.environ.get("OPS_BASIC_PASSWORD")
    if user or password:      # 只给本地开发用；生产走 console.json
        return user or "qingsu", password or ""
    d = _secret_blob()
    return str(d.get("basic_user") or "qingsu"), str(d.get("basic_password") or "")


def _secret_blob() -> dict:
    global _secrets_cache
    if "blob" not in _secrets_cache:
        token, cookie = load_secrets()
        try:
            blob = json.loads(Path(SECRET_FILE).read_text(encoding="utf-8"))
        except Exception:
            blob = {}
        _secrets_cache["blob"] = blob
    return _secrets_cache["blob"]


# ---------------------------------------------------------------- 应用

app = FastAPI(title="qingsu-ops", docs_url=None, redoc_url=None)


@app.middleware("http")
async def basic_gate_middleware(request: Request, call_next):
    """L2：整台服务都在这道闸后面，没有例外（包括 /api/login）。
    口令没配好时宁可 503 拒绝服务，也不静默敞开——"忘了配 Basic"这种事
    最坏的形状是它一直开着而没人知道。"""
    # Browser writes carrying cookies must originate from this same site.
    origin = request.headers.get('origin')
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and origin:
        from urllib.parse import urlsplit
        parsed = urlsplit(origin)
        if parsed.netloc != request.headers.get('host') or parsed.scheme not in ('https', 'http'):
            return JSONResponse({'detail': '拒绝跨站后台操作'}, status_code=403)
    user, password = basic_gate()
    challenge = 'Basic realm="qingsu-ops", charset="UTF-8"'
    if not password:
        return JSONResponse({"detail": "后台 Basic 口令未配置"}, status_code=503,
                            headers={"WWW-Authenticate": challenge})
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        raw = None
        try:
            raw = base64.b64decode(header[6:].strip()).decode("utf-8")
        except Exception:
            raw = None      # 解不开就等于没授权，不区分原因，免得给探测留差异信号
        if raw:
            got_user, _, got_password = raw.partition(":")
            if hmac.compare_digest(got_user, user) and hmac.compare_digest(got_password, password):
                # 注意：call_next 必须放在 try 外面。放在里面的话，下游任何异常都会被
                # 这个 except 吞掉并返回 401——排查时看起来像"口令错"，实际是接口炸了（本轮踩过）。
                response = await call_next(request)
                response.headers["Cache-Control"] = "private, no-store"
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["Referrer-Policy"] = "no-referrer"
                return response
    return JSONResponse({"detail": "需要后台 Basic 口令"}, status_code=401,
                        headers={"WWW-Authenticate": challenge})


# 后台依赖的主应用结构（方案 C05 的版本配对）。这两仓共用一个库，
# 后台先上、主应用后上，就会以"某列不存在"的形状炸在一条高危操作上——
# 而高危操作炸在写完之后，正是"界面报错、实际已改"那一类。
# 直接查库看列在不在，比信主应用自己报的版本更硬：它俩本来就同一个库。
APP_REQUIRED_COLUMNS = {
    "users": ("reset_expires_at", "reset_consumed"),
    "food_logs": ("occurred_at",),
    "workout_logs": ("occurred_at",),
}
ADMIN_REVISION = os.environ.get("QINGSU_ADMIN_REVISION", "unknown")


def missing_app_columns() -> list[str]:
    conn = db(readonly=True)
    try:
        out = []
        for table, wanted in sorted(APP_REQUIRED_COLUMNS.items()):
            have = set(columns(conn, table))
            out += ["%s.%s" % (table, name) for name in wanted if name not in have]
        return out
    except sqlite3.Error:
        return ["(业务库结构读不出来)"]
    finally:
        conn.close()


def require_app_schema() -> None:
    missing = missing_app_columns()
    if missing:
        raise HTTPException(status_code=503,
                            detail="主应用结构还没升到后台要求的版本，缺 %s：先升级主服务再做这一步"
                                   % "、".join(missing))


def version_pairing() -> dict:
    """把"主应用是哪版、后台是哪版、结构对不对得上"摊在一处（方案 C03/C04 要的配对记录）。"""
    ready, err = json_get(APP_API + "/health/ready")
    missing = missing_app_columns()
    return {"admin_revision": ADMIN_REVISION,
            "app_release": (ready or {}).get("release"),
            "app_schema_version": (ready or {}).get("schema_version"),
            "app_schema_required": (ready or {}).get("schema_required"),
            "app_version": (ready or {}).get("version"),
            "app_error": err,
            "paired": not missing and err is None,
            "missing_app_columns": missing}


@app.get("/api/version-pairing")
def version_pairing_route(actor: str = Depends(actor_of)):
    out = version_pairing()
    out["note"] = ("paired 为假时不要发后台：两仓共用一个库，"
                   "后台先上会让高危操作写到还不存在的列上")
    return out


@app.on_event("startup")
def _startup() -> None:
    conn = db()
    try:
        conn.execute(AUDIT_SQL)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON admin_audit(id DESC)")
        conn.commit()
    finally:
        conn.close()
    if not os.path.exists(DB_PATH):
        log.error("业务库不存在 path=%s", DB_PATH)
    if os.environ.get("OPS_TOKEN") and not os.environ.get("ALLOW_ENV_TOKEN"):
        log.warning("OPS_TOKEN 走环境变量：只适合本地开发，生产要落 root:600 文件")
    missing = missing_app_columns()
    if missing:
        # 起得来但结构不对：说清缺什么，别等第一条高危操作才发现
        log.error("admin_schema_behind missing=%s app=%s", ",".join(missing), APP_API)


def json_get(url: str, timeout: float = 6.0):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        return None, "http_%d" % e.code
    except Exception as e:
        # 只报类型名：异常文本可能带上 URL 或凭据
        return None, "error_" + type(e).__name__


@app.post("/api/login")
def login(body: dict, request: Request, response: Response):
    ip = client_ip(request)
    hits, until = _attempts.get(ip, (0, 0.0))
    if until > time.time():
        raise HTTPException(status_code=429, detail="尝试太多，%d 秒后再试" % int(until - time.time()))
    token, _ = load_secrets()
    supplied = str((body or {}).get("token") or "")
    named = str((body or {}).get("operator") or "").strip()
    operators = operator_tokens()
    actor = None
    ambiguous = False
    if supplied:
        if named:
            if named in operators and hmac.compare_digest(supplied, operators[named]):
                actor = named
        else:
            # 没报名字就只在"唯一一把凭据对得上"时放行：多管理员之后，
            # 拿一把口令猜不出是谁，就不该顶掉某个具体的人。
            matches = [name for name, secret in operators.items()
                       if hmac.compare_digest(supplied, secret)]
            actor = matches[0] if len(matches) == 1 else None
            ambiguous = len(matches) > 1
    ok = actor is not None
    if not ok:
        locked = hits + 1 >= LOGIN_MAX_ATTEMPTS
        _attempts[ip] = (hits + 1, time.time() + LOGIN_LOCK_SEC if locked else 0.0)
        audit("anonymous", "login_failed", "ip", ip,
              note="第 %d 次%s" % (hits + 1,
                                   "（多把凭据命中同一口令，请带 operator）" if ambiguous
                                   else ""))
        raise HTTPException(status_code=401, detail="运维令牌不对")
    _attempts.pop(ip, None)
    response.set_cookie("qops", make_session(actor), max_age=SESSION_TTL,
                        httponly=True, samesite="strict",
                        secure=os.environ.get("OPS_INSECURE_COOKIE") != "1", path="/")
    audit(actor, "login", "ip", ip)
    return {"code": 0, "operator": actor, "expires_in": SESSION_TTL,
            "idle_expires_in": SESSION_IDLE_TTL}


@app.post("/api/logout")
def logout(request: Request, response: Response, actor: str = Depends(actor_of)):
    conn = db()
    try:
        ensure_ops_schema(conn)
        conn.execute("DELETE FROM ops_sessions WHERE token_hash=?", (hashlib.sha256(request.cookies.get("qops", "").encode()).hexdigest(),))
        audit_in(conn, actor, "logout")
        conn.commit()
    finally:
        conn.close()
    response.delete_cookie("qops", path="/")
    return {"code": 0}


@app.get("/api/sessions")
def sessions_list(actor: str = Depends(actor_of)):
    """现在谁还在线。只出哈希前 8 位——会话令牌本身不能从后台读回来。"""
    now = int(time.time())
    conn = db(readonly=True)
    try:
        rows = conn.execute("SELECT token_hash,actor,created_at,last_seen_at,absolute_expires_at,"
                            "credential_fp FROM ops_sessions ORDER BY last_seen_at DESC LIMIT 200").fetchall()
    except sqlite3.Error:
        return {"items": [], "note": "还没有任何后台会话"}
    finally:
        conn.close()
    known = operator_tokens()
    items = [{"session": r["token_hash"][:8],
              "actor": r["actor"],
              "created_at": r["created_at"],
              "last_seen": r["last_seen_at"],
              "idle_left_seconds": max(0, r["last_seen_at"] + SESSION_IDLE_TTL - now),
              "absolute_left_seconds": max(0, r["absolute_expires_at"] - now),
              "credential_rotated": credential_fp(known.get(r["actor"], "")) != r["credential_fp"]}
             for r in rows]
    return {"items": items, "count": len(items),
            "note": "idle_left 是空闲到期，absolute_left 是绝对到期；两者任一到期都要重新登录"}


@app.post("/api/sessions/revoke")
def sessions_revoke(body: dict, actor: str = Depends(actor_of)):
    """把某个命名账号名下的会话全部撤掉（换人、口令泄露、脚本停用都走这里）。
    撤自己也要能撤——所以不要求额外口令，但必须原样带回目标账号名，防误点。"""
    target = str((body or {}).get("target_actor") or "").strip()
    if not target:
        raise HTTPException(status_code=422, detail="要撤销谁的会话，得把名字带回来")
    if target != actor and (body or {}).get("confirm") != ("撤销 " + target + " 的全部后台会话"):
        raise HTTPException(status_code=409, detail="撤销别人的会话要原样带回确认短语")
    n = revoke_actor_sessions(target)
    audit(actor, "revoke_admin_sessions", "admin_session", target, after={"revoked": n})
    return {"code": 0, "revoked": n}


@app.get("/api/whoami")
def whoami(actor: str = Depends(actor_of)):
    return {"actor": actor, "at": now_iso()}


# ---------------------------------------------------------------- 只读


# 降权之后（方案 C01）：需要 root 的三件事改成 sudo 调参数白名单 helper。
# 没配 helper 时退回"本进程直接做"，那是本地开发和测试的形状——生产 unit 必须三个都配上，
# 缺哪个就在 /api/privileged 里看得见，不会悄悄以 root 跑回去。
GATE_HELPER = os.environ.get("QINGSU_GATE_HELPER", "")
BACKUP_HELPER = os.environ.get("QINGSU_BACKUP_HELPER", "")
HEALTH_HELPER = os.environ.get("QINGSU_HEALTH_HELPER", "")
SUDO = [s for s in os.environ.get("QINGSU_SUDO", "sudo -n").split() if s]


def helper_configured() -> dict:
    return {"gate": bool(GATE_HELPER), "backup": bool(BACKUP_HELPER),
            "health": bool(HEALTH_HELPER),
            "effective_uid": getattr(os, 'geteuid', lambda: None)(),
            "service_user": os.environ.get("QINGSU_OPS_USER", "unknown")}


def run_privileged(kind: str, argv: list[str], fallback, timeout: float = 600):
    """走 helper，或者在没有 helper 时执行 fallback（本进程直接做）。

    fallback 只在开发机与测试夹具里用得到；生产上它等价于"这个进程还是 root"。
    """
    helper = {"gate": GATE_HELPER, "backup": BACKUP_HELPER, "health": HEALTH_HELPER}[kind]
    if not helper:
        return fallback()
    proc = subprocess.run([*SUDO, helper, *argv], capture_output=True, text=True, timeout=timeout)
    return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


@app.get("/api/privileged")
def privileged_route(actor: str = Depends(actor_of)):
    out = helper_configured()
    missing = [k for k, on in (("gate", out["gate"]), ("backup", out["backup"]),
                               ("health", out["health"])) if not on]
    out["missing_helpers"] = missing
    out["note"] = ("配了 helper 时这三件事经 sudo 走参数白名单脚本；没配则本进程直接做，"
                   "那要求进程本身有 root 位——生产 unit 不该再是 root"
                   + ("；还缺 " + "、".join(missing) if missing else ""))
    return out


@app.get("/api/health")
def health(actor: str = Depends(actor_of)):
    ready, ready_err = json_get(APP_API + "/health/ready")
    container = "unknown"
    try:
        def direct():
            proc = subprocess.run(["docker", "inspect", "-f",
                                   "{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}",
                                   CONTAINER_NAME], capture_output=True, text=True, timeout=8)
            return {"stdout": proc.stdout or proc.stderr}
        result = run_privileged("health", [CONTAINER_NAME], direct, timeout=8)
        container = ((result.get("stdout") or "") or "unknown").strip()
        if result.get("returncode"):
            container = "helper_failed_" + str(result["returncode"])
    except Exception as e:
        container = "error_" + type(e).__name__
    disk = shutil.disk_usage(os.path.dirname(DB_PATH))
    mem: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines()[:3]:
            k, v = line.split(":", 1)
            mem[k.lower()] = int(v.strip().split()[0]) // 1024
    except Exception:
        mem = {}
    backup_listing = 'available'
    try:
        backups = sorted(os.listdir(BACKUP_DIR))[-3:]
    except FileNotFoundError:
        backups = []
    except PermissionError:
        backups = None
        backup_listing = 'restricted'
    return {"app": ready if ready is not None else {"unreachable": ready_err},
            "console_container": container,
            "disk_free_mb": disk.free // 1024 // 1024,
            "mem_mb": mem, "recent_backups": backups, "backup_listing": backup_listing, "ops_time": now_iso()}


@app.get("/api/overview")
def overview(actor: str = Depends(actor_of)):
    """看板数字全部从明细表现算（docs/01 M-51）。
    Directus 读不到那 12 张没有单列整数主键的表，所以点赞/关注/喝水这类计数只能由本接口出。"""
    conn = db(readonly=True)
    try:
        counts: dict[str, int | None] = {}
        for table in ("users", "posts", "comments", "post_likes", "follows", "user_blocks",
                      "messages", "conversations", "notifications", "feedback", "content_reports",
                      "media_uploads", "food_logs", "weight_logs", "water_logs", "sessions"):
            try:
                counts[table] = conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]
            except sqlite3.Error:
                counts[table] = None        # 表不存在＝如实的 None，不是 0
        users = counts["users"] or 0
        regioned = conn.execute("SELECT COUNT(*) FROM community_profile "
                                "WHERE region IS NOT NULL AND region<>''").fetchone()[0]
        provinces = [dict(r) for r in conn.execute(
            "SELECT region, COUNT(*) AS users FROM community_profile "
            "WHERE region IS NOT NULL AND region<>'' GROUP BY region "
            "ORDER BY users DESC LIMIT 12").fetchall()]
        pending = {
            "feedback_new": conn.execute("SELECT COUNT(*) FROM feedback WHERE status='new'").fetchone()[0],
            "reports_open": conn.execute("SELECT COUNT(*) FROM content_reports WHERE status='open'").fetchone()[0],
            "banned": conn.execute("SELECT COUNT(*) FROM users WHERE banned_at IS NOT NULL").fetchone()[0],
        }
    finally:
        conn.close()
    ready, err = json_get(APP_API + "/health/ready")
    return {"counts": counts,
            "region": {"with_region": regioned, "total": users,
                       "ratio": round(regioned / users, 4) if users else None,
                       "provinces": provinces,
                       "hint": ("有属地的用户不足一半时，同城页签多半是空的"
                                if users and regioned * 2 < users else "")},
            "pending": pending,
            "gate": (ready or {}).get("gate", {"unreachable": err}),
            "chat": (ready or {}).get("chat", {"unreachable": err}),
            "keys": (ready or {}).get("keys", {"unreachable": err})}


def page_result(rows, limit):
    more = len(rows) > limit
    items = rows[:limit]
    return {"items": items, "more": more, "next_cursor": int(items[-1]["id"]) if more else 0}


def checked_cursor(cursor):
    if cursor < 0:
        raise HTTPException(422, "翻页游标不能为负数")
    return cursor


@app.get("/api/feedback")
def feedback_list(status: str = "", limit: int = 20, cursor: int = 0, kind: str = "", build: int = 0, actor: str = Depends(actor_of)):
    if status not in ("", "new", "doing", "done", "wontfix") or kind not in ("", "bug", "idea", "data", "other"):
        raise HTTPException(422, "反馈筛选不合法")
    checked_cursor(cursor)
    limit = max(1, min(int(limit or 20), 50))
    conn = db(readonly=True)
    try:
        filters, params = [], []
        for column, value in (("status", status), ("kind", kind), ("app_build", build)):
            if value:
                filters.append(column + "=?"); params.append(value)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        total = conn.execute("SELECT COUNT(*) FROM feedback" + where, params).fetchone()[0]
        if cursor:
            filters.append("id<?"); params.append(cursor)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        items = [dict(r) for r in conn.execute(
            "SELECT id,user_id,kind,status,substr(body,1,160) AS body,page,app_build,contact,substr(reply,1,160) AS reply,created_at,replied_at FROM feedback" + where + " ORDER BY id DESC LIMIT ?", (*params, limit + 1))]
        counts = {r[0]: r[1] for r in conn.execute("SELECT status, COUNT(*) FROM feedback GROUP BY status")}
        return {**page_result(items, limit), "counts": counts, "total": total}
    finally:
        conn.close()


@app.get("/api/feedback/{feedback_id}")
def feedback_detail(feedback_id: int, actor: str = Depends(actor_of)):
    conn = db(readonly=True)
    try:
        row = conn.execute(
            "SELECT id,user_id,kind,status,body,page,app_build,contact,reply,created_at,replied_at "
            "FROM feedback WHERE id=?", (feedback_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="反馈不存在")
        item = dict(row)
        item["username"] = (conn.execute("SELECT username FROM users WHERE id=?",
                                         (item["user_id"],)).fetchone() or [None])[0] \
            if item["user_id"] is not None else None
        return item
    finally:
        conn.close()


@app.patch("/api/feedback/{feedback_id}")
def update_feedback(feedback_id: int, payload: dict, actor: str = Depends(actor_of)):
    """Update a support ticket and keep the customer-facing feedback API in sync."""
    statuses = {"new", "doing", "done", "wontfix"}
    status = str(payload.get("status") or "")
    expected = str(payload.get("expected_status") or "")
    if status not in statuses or expected not in statuses:
        raise HTTPException(status_code=422, detail="状态或原状态不合法")
    if "reply" not in payload or not isinstance(payload.get("reply"), str):
        raise HTTPException(status_code=422, detail="请填写处理回复")
    reply = payload["reply"].strip()
    if len(reply) > 800:
        raise HTTPException(status_code=422, detail="回复最多 800 字")
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT id,user_id,kind,status,reply FROM feedback WHERE id=?",
                           (feedback_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="反馈不存在")
        if row["status"] != expected:
            raise HTTPException(status_code=409, detail="反馈已被其他操作更新，请刷新后重试")
        replied_at = now_iso() if reply else None
        conn.execute("UPDATE feedback SET status=?,reply=?,replied_at=COALESCE(?,replied_at) WHERE id=?",
                     (status, reply, replied_at, feedback_id))
        audit_in(conn, actor, "update_feedback", "feedback", feedback_id,
                 before={"status": row["status"], "reply_length": len(row["reply"] or "")},
                 after={"status": status, "reply_length": len(reply)})
        conn.commit()
        return {"code": 0, "id": feedback_id, "status": status,
                "reply": reply, "replied_at": replied_at}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/api/reports")
def reports_list(status: str = "open", limit: int = 20, cursor: int = 0, target_kind: str = "", actor: str = Depends(actor_of)):
    if status not in ("open", "actioned", "dismissed", "all"):
        raise HTTPException(status_code=422, detail="举报状态不合法")
    checked_cursor(cursor)
    if target_kind not in ("", "post", "comment", "user"):
        raise HTTPException(422, "举报对象类型不合法")
    limit = max(1, min(int(limit or 20), 50))
    conn = db(readonly=True)
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(content_reports)")}
        if not {"status", "handled_at", "handled_note"} <= have:
            raise HTTPException(status_code=503, detail="主应用数据库尚未完成举报状态迁移")
        wanted = ["id", "target_kind", "target_id", "reporter", "reason", "created_at",
                  "status", "handled_at", "handled_note"]
        filters, args = [], []
        if status != "all": filters.append("status=?"); args.append(status)
        if target_kind: filters.append("target_kind=?"); args.append(target_kind)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        total = conn.execute("SELECT COUNT(*) FROM content_reports" + where, args).fetchone()[0]
        if cursor: filters.append("id<?"); args.append(cursor)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        rows = conn.execute("SELECT %s FROM content_reports %s ORDER BY id DESC LIMIT ?" % (",".join(wanted), where), (*args, limit + 1)).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        counts = {str(r[0]): int(r[1]) for r in conn.execute(
            "SELECT status,COUNT(*) FROM content_reports GROUP BY status").fetchall()}
        items = []
        for row in rows:
            item = dict(row)
            reporter = conn.execute("SELECT username,nickname FROM users WHERE id=?",
                                    (item["reporter"],)).fetchone()
            item["reporter_name"] = ((reporter["nickname"] or reporter["username"]) if reporter else "已注销用户")
            target = None
            if item["target_kind"] == "post":
                target = conn.execute(
                    "SELECT p.id,p.user_id,p.body,p.status,u.username,u.nickname "
                    "FROM posts p LEFT JOIN users u ON u.id=p.user_id WHERE p.id=?",
                    (item["target_id"],)).fetchone()
            elif item["target_kind"] == "comment":
                target = conn.execute(
                    "SELECT c.id,c.post_id,c.user_id,c.body,c.status,u.username,u.nickname "
                    "FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE c.id=?",
                    (item["target_id"],)).fetchone()
            item["target"] = (dict(target) if target else None)
            if item["target"]:
                item["target"]["author"] = (item["target"].pop("nickname", None)
                                               or item["target"].pop("username", None)
                                               or "已注销用户")
            items.append(item)
        return {"items": items, "counts": counts, "status": status, "total": total, "more": more, "next_cursor": int(items[-1]["id"]) if more else 0}
    finally:
        conn.close()


@app.post("/api/reports/{report_id}/resolve")
def resolve_report(report_id: int, payload: dict, actor: str = Depends(actor_of)):
    action = str(payload.get("action") or "")
    expected = str(payload.get("expected_status") or "")
    note = str(payload.get("note") or "").strip()
    if action not in ("dismiss", "remove") or expected != "open":
        raise HTTPException(status_code=422, detail="处理动作或原状态不合法")
    if len(note) < 2 or len(note) > 400:
        raise HTTPException(status_code=422, detail="请填写 2–400 字的处理说明")
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        report = conn.execute("SELECT * FROM content_reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            raise HTTPException(status_code=404, detail="举报不存在")
        if report["status"] != expected:
            raise HTTPException(status_code=409, detail="举报已被处理，请刷新队列")
        target_kind, target_id = report["target_kind"], int(report["target_id"])
        before_target = None
        action_name = "dismiss_report"
        final_status = "dismissed"
        if action == "remove":
            if target_kind == "post":
                target = conn.execute("SELECT id,status FROM posts WHERE id=?", (target_id,)).fetchone()
                if not target or target["status"] != "open":
                    raise HTTPException(status_code=409, detail="帖子已不存在或已下架")
                before_target = {"status": target["status"]}
                conn.execute("UPDATE posts SET status='deleted' WHERE id=? AND status='open'", (target_id,))
                action_name = "remove_reported_post"
            elif target_kind == "comment":
                target = conn.execute("SELECT id,post_id,status FROM comments WHERE id=?",
                                      (target_id,)).fetchone()
                if not target or target["status"] != "open":
                    raise HTTPException(status_code=409, detail="评论已不存在或已删除")
                before_target = {"status": target["status"]}
                conn.execute("UPDATE comments SET status='deleted' WHERE id=? AND status='open'", (target_id,))
                conn.execute("UPDATE posts SET comment_count=MAX(0,comment_count-1) WHERE id=?",
                             (target["post_id"],))
                action_name = "remove_reported_comment"
            else:
                raise HTTPException(status_code=422, detail="不支持的举报对象类型")
            final_status = "actioned"
        conn.execute("UPDATE content_reports SET status=?,handled_at=?,handled_note=? WHERE id=? AND status='open'",
                     (final_status, now_iso(), note, report_id))
        audit_in(conn, actor, action_name, target_kind, target_id,
                 before={"report_status": "open", "target": before_target} if before_target else {"report_status": "open"},
                 after={"report_status": final_status,
                        "target_status": "deleted" if action == "remove" else None}, note=note)
        conn.commit()
        return {"code": 0, "id": report_id, "status": final_status,
                "target_kind": target_kind, "target_id": target_id}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/api/users")
def list_users(q: str = "", limit: int = 20, cursor: int = 0, actor: str = Depends(actor_of)):
    checked_cursor(cursor)
    limit = max(1, min(int(limit or 20), 50))
    conn = db(readonly=True)
    try:
        cols = ",".join(safe_columns(conn, "users"))
        term = str(q or "").strip()[:60]
        filters, args = [], []
        if term:
            filters.append("(CAST(id AS TEXT)=? OR username LIKE ? OR nickname LIKE ? OR public_id LIKE ?)")
            args.extend((term, *(["%" + term + "%"] * 3)))
        where = " WHERE " + " AND ".join(filters) if filters else ""
        total = conn.execute("SELECT COUNT(*) FROM users" + where, args).fetchone()[0]
        if cursor: filters.append("id<?"); args.append(cursor)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        rows = [dict(r) for r in conn.execute("SELECT " + cols + " FROM users" + where + " ORDER BY id DESC LIMIT ?", (*args, limit + 1))]
        result = page_result(rows, limit)
        ids = tuple(row['id'] for row in result['items'])
        sessions = {row[0]: row[1] for row in conn.execute("SELECT user_id,COUNT(*) FROM sessions WHERE user_id IN (" + ','.join('?' for _ in ids) + ") GROUP BY user_id", ids)} if ids else {}
        for row in result['items']: row['sessions'] = sessions.get(row['id'], 0)
        return {**result, "count": len(result['items']), "total": total, "query": term}
    finally:
        conn.close()


@app.get("/api/users/{uid}")
def user_detail(uid: int, actor: str = Depends(actor_of)):
    conn = db(readonly=True)
    try:
        cols = ",".join(safe_columns(conn, "users"))
        row = conn.execute("SELECT %s FROM users WHERE id=?" % cols, (uid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="没有这个用户")
        out = {"user": dict(row), "counts": {}}
        for table, col in user_refs(conn):
            if table == "users":
                continue
            try:
                n = conn.execute("SELECT COUNT(*) FROM %s WHERE %s=?" % (table, col), (uid,)).fetchone()[0]
            except sqlite3.Error:
                continue
            if n:
                out["counts"][table] = out["counts"].get(table, 0) + n
        out["last_seen"] = conn.execute(
            "SELECT MAX(expires_at) AS m FROM sessions WHERE user_id=?", (uid,)).fetchone()["m"]
        return out
    finally:
        conn.close()


@app.get("/api/users/{uid}/export")
def export_user(uid: int, actor: str = Depends(actor_of)):
    conn = db(readonly=True)
    try:
        cols = ",".join(safe_columns(conn, "users"))
        row = conn.execute("SELECT %s FROM users WHERE id=?" % cols, (uid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="没有这个用户")
        out: dict = {"user": dict(row), "tables": {}}
        for table, col in user_refs(conn):
            if table == "users":
                continue
            try:
                want = ",".join(safe_columns(conn, table))
                if not want:
                    continue
                rows = conn.execute("SELECT %s FROM %s WHERE %s=?" % (want, table, col),
                                    (uid,)).fetchall()
            except sqlite3.Error:
                continue
            if rows:
                out["tables"].setdefault(table, [])
                for r in rows:
                    item = _redact_table(table, dict(r))
                    if table == "conversations":
                        item.pop("last_body", None)
                    if table == "messages" and item.get("recalled_at"):
                        for field in ("body", "media_name", "media_meta", "quote_snippet", "quote_name", "asr_text"):
                            item.pop(field, None)
                    if item not in out["tables"][table]:
                        out["tables"][table].append(item)
        out["actor"] = actor
        out["exported_at"] = now_iso()
        audit(actor, "export_user", "users", uid, after={"tables": len(out["tables"])})
        return out
    finally:
        conn.close()


def _redact_table(table: str, row: dict) -> dict:
    return {k: v for k, v in row.items() if (table, k) not in SENSITIVE}


@app.get("/api/audit")
def audit_list(limit: int = 40, cursor: int = 0, action: str = "", target_kind: str = "", actor: str = Depends(actor_of)):
    checked_cursor(cursor)
    limit = max(1, min(int(limit or 40), 200))
    conn = db(readonly=True)
    try:
        filters, args = [], []
        for column, value in (("action", action), ("target_kind", target_kind)):
            if value: filters.append(column + "=?"); args.append(value.strip()[:100])
        where = " WHERE " + " AND ".join(filters) if filters else ""
        total = conn.execute("SELECT COUNT(*) FROM admin_audit" + where, args).fetchone()[0]
        if cursor: filters.append("id<?"); args.append(cursor)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        page = page_result([dict(r) for r in conn.execute("SELECT * FROM admin_audit" + where + " ORDER BY id DESC LIMIT ?", (*args, limit + 1))], limit)
        rows = page['items']
    finally:
        conn.close()
    for r in rows:
        for key in ("before_json", "after_json"):
            try:
                payload = json.loads(r[key]) if r[key] else None
            except json.JSONDecodeError:
                payload = "非JSON(截断)"
            if isinstance(payload, dict):
                payload = _redact_table(str(r.get("target_kind") or ""), payload)
            r[key] = payload
    return {**page, "total": total}


# ---------------------------------------------------------------- 高危


def dependent_rows(conn: sqlite3.Connection, uid: int) -> list[dict]:
    """别人留在该用户帖子上的点赞/评论/收藏。它们引用的是帖子，不是发帖人；
    只按 user_id 删用户行会留下"指向已删帖子"的外键，整笔删号会回滚。
    只算别人的行（user_id<>?），避免与 user_refs 的清单重复计数。"""
    out = []
    for table, col in (("post_likes", "post_id"), ("comments", "post_id"),
                       ("post_favorites", "post_id")):
        try:
            n = conn.execute(
                "SELECT COUNT(*) FROM %s WHERE %s IN (SELECT id FROM posts WHERE user_id=?)"
                " AND user_id<>?" % (table, col), (uid, uid)).fetchone()[0]
        except sqlite3.Error:
            continue
        if n:
            out.append({"table": table, "column": col, "rows": n})
    for table, col in (("comment_likes", "comment_id"), ("mentions", "comment_id")):
        n = conn.execute("SELECT COUNT(*) FROM " + table + " WHERE comment_id IN (SELECT id FROM comments WHERE user_id=? OR post_id IN (SELECT id FROM posts WHERE user_id=?)) AND user_id<>?", (uid, uid, uid)).fetchone()[0]
        if n:
            out.append({"table": table, "column": col, "rows": n, "scope": "comment"})
    return out


def _load_user_for_action(conn: sqlite3.Connection, uid: int, expect_username) -> sqlite3.Row:
    """所有高危动作的第一道闸：必须把用户名原样带回来，且与服务端查到的完全一致。
    这一条不是防"误点"，是防"看着列表第 3 行就动手"。"""
    if not str(expect_username or "").strip():
        raise HTTPException(status_code=422, detail="必须回显用户名")
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="没有这个用户")
    if row["username"] != str(expect_username).strip():
        raise HTTPException(status_code=409, detail="用户名与这个 id 对不上，动作没执行")
    return row


@app.post("/api/users/{uid}/nickname")
def rename_user(uid: int, body: dict, actor: str = Depends(actor_of)):
    nick = str((body or {}).get("nickname") or "").strip()[:20]
    if not nick:
        raise HTTPException(status_code=422, detail="昵称不能为空（最多 20 字）")
    conn = db()
    try:
        row = _load_user_for_action(conn, uid, (body or {}).get("expect_username"))
        before = {"nickname": row["nickname"]}
        conn.execute("UPDATE users SET nickname=? WHERE id=?", (nick, uid))
        audit_in(conn, actor, "rename_user", "users", uid, before=before, after={"nickname": nick})
        conn.commit()
        return {"code": 0, "nickname": nick}
    finally:
        conn.close()


@app.get("/api/media/orphans")
def media_orphans(actor: str = Depends(actor_of)):
    """只报告，不删。文件名属于敏感列（docs/02 §3），这里只回数量与体积。"""
    if not os.path.isdir(UPLOAD_DIR):
        return {"files": 0, "referenced": 0, "orphans": None, "orphan_bytes": None,
                "note": "上传目录不存在"}
    names = {n for n in os.listdir(UPLOAD_DIR) if os.path.isfile(os.path.join(UPLOAD_DIR, n))}
    conn = db(readonly=True)
    referenced = set()

    def add(name: str) -> None:
        """登记一个被引用的文件；缩略图跟着原图一起算。

        缩略图不落任何表（按需生成，文件名就是 原图名 + .thumb.jpg），
        只按"表里出现过的文件名"比对的话，每张有效图的缩略图都会被报成孤儿——
        这正是 A10 要修的那类错：统计不可信，将来照它清理就会误伤。
        """
        base = os.path.basename(str(name or ""))
        if not base:
            return
        referenced.add(base)
        if base.endswith(".thumb.jpg"):
            referenced.add(base[:-len(".thumb.jpg")])
        else:
            referenced.add(base + ".thumb.jpg")

    try:
        for row in conn.execute("SELECT photo_url FROM body_cycles WHERE photo_url IS NOT NULL AND photo_url<>''"):
            add(row[0])
        for row in conn.execute("SELECT avatar_url FROM profiles WHERE avatar_url IS NOT NULL AND avatar_url<>''"):
            add(row[0])
        for row in conn.execute("SELECT images FROM posts WHERE images IS NOT NULL AND images<>''"):
            # posts.images 存的是 /uploads/xxx.jpg 这种带路径的 URL，和文件名比对前必须取 basename
            for n in read_images(row[0]):
                add(n)
        for row in conn.execute("SELECT images FROM comments WHERE images IS NOT NULL AND images<>''"):
            for n in read_images(row[0]):
                add(n)
        for row in conn.execute("SELECT name FROM media_uploads WHERE kind='sticker'"):
            add(row[0])
        # 私聊里的图片/视频也是被引用的文件；漏掉会把聊天媒体全报成孤儿
        for row in conn.execute("SELECT media_name FROM messages WHERE media_name IS NOT NULL AND media_name<>''"):
            add(row[0])
    finally:
        conn.close()
    orphans = sorted(names - referenced)
    size = 0
    for n in orphans:
        try:
            size += os.path.getsize(os.path.join(UPLOAD_DIR, n))
        except OSError:
            pass
    return {"files": len(names), "referenced": len(names & referenced), "orphans": len(orphans),
            "orphan_bytes": size, "note": "只报告；清理请走主应用的 quarantine-orphans.py"}


@app.get("/api/users/{uid}/messages/export")
def export_messages(uid: int, with_user: int = 0, actor: str = Depends(actor_of)):
    """导出某段会话（处理纠纷用）。已撤回的消息只给"已撤回"，正文不出。"""
    if not with_user:
        raise HTTPException(status_code=422, detail="要带 with_user（另一个人的 id）")
    conn = db(readonly=True)
    try:
        a = conn.execute("SELECT id,username,public_id FROM users WHERE id=?", (uid,)).fetchone()
        b = conn.execute("SELECT id,username,public_id FROM users WHERE id=?", (with_user,)).fetchone()
        if not a or not b:
            raise HTTPException(status_code=404, detail="会话一方不存在")
        key = "%d:%d" % (min(uid, with_user), max(uid, with_user))
        rows = conn.execute(
            "SELECT id,from_id,to_id,body,created_at,recalled_at FROM messages "
            "WHERE conv_key=? ORDER BY id ASC LIMIT 5000", (key,)).fetchall()
        items = [{"id": int(r["id"]), "from_id": int(r["from_id"]), "to_id": int(r["to_id"]),
                  "body": "" if r["recalled_at"] else r["body"],
                  "recalled": bool(r["recalled_at"]), "created_at": r["created_at"]}
                 for r in rows]
    finally:
        conn.close()
    audit(actor, "export_dm", "users", uid, after={"with_user": with_user, "messages": len(items)})
    return {"a": dict(a), "b": dict(b), "messages": items}


@app.post("/api/users/{uid}/ban")
def ban(uid: int, body: dict, actor: str = Depends(actor_of)):
    reason = str((body or {}).get("reason") or "").strip()[:200]
    if not reason:
        raise HTTPException(status_code=422, detail="封号要写原因，不然用户来问没人答得上")
    conn = db()
    try:
        row = _load_user_for_action(conn, uid, (body or {}).get("expect_username"))
        before = {"banned_at": row["banned_at"], "ban_reason": row["ban_reason"]}
        if row["banned_at"]:
            audit(actor, "ban", "users", uid, before=before, after=before, note="已是封号态，未改动")
            return {"code": 0, "already": True, "banned_at": row["banned_at"]}
        stamp = now_iso()
        conn.execute("UPDATE users SET banned_at=?, ban_reason=? WHERE id=?", (stamp, reason, uid))
        audit_in(conn, actor, "ban", "users", uid, before=before,
              after={"banned_at": stamp, "ban_reason": reason})
        conn.commit()
        return {"code": 0, "banned_at": stamp}
    finally:
        conn.close()


@app.post("/api/users/{uid}/unban")
def unban(uid: int, body: dict, actor: str = Depends(actor_of)):
    conn = db()
    try:
        row = _load_user_for_action(conn, uid, (body or {}).get("expect_username"))
        before = {"banned_at": row["banned_at"], "ban_reason": row["ban_reason"]}
        conn.execute("UPDATE users SET banned_at=NULL, ban_reason='' WHERE id=?", (uid,))
        audit_in(conn, actor, "unban", "users", uid, before=before,
              after={"banned_at": None, "ban_reason": ""})
        conn.commit()
        return {"code": 0}
    finally:
        conn.close()


@app.post("/api/users/{uid}/revoke-sessions")
def revoke_sessions(uid: int, body: dict, actor: str = Depends(actor_of)):
    conn = db()
    try:
        _load_user_for_action(conn, uid, (body or {}).get("expect_username"))
        n = conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (uid,)).fetchone()[0]
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        audit_in(conn, actor, "revoke_sessions", "users", uid, before={"sessions": n}, after={"sessions": 0})
        conn.commit()
        return {"code": 0, "revoked": n}
    finally:
        conn.close()


@app.post("/api/users/{uid}/reset-password")
def reset_password(uid: int, body: dict, actor: str = Depends(actor_of),
                   _paired: None = Depends(require_app_schema)):
    """改口令必须连带撤销全部会话：否则旧 token 在新口令之下仍然可用，
    "我给她换了密码所以踢掉了登录"就是句假话。"""
    conn = db()
    try:
        row = _load_user_for_action(conn, uid, (body or {}).get("expect_username"))
        otp = gen_otp_password()
        salt, pw_hash = make_pw(otp)
        sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (uid,)).fetchone()[0]
        conn.execute("UPDATE users SET password_hash=?, pw_salt=?,reset_expires_at=?,reset_consumed=0 WHERE id=?", (pw_hash, salt, int(time.time()) + 1800, uid))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        # 一次性口令本身不落库、不进日志，只在响应里出现一次
        audit_in(conn, actor, "reset_pw", "users", uid,
              before={"username": row["username"], "sessions": sessions},
              after={"sessions": 0, "otp_delivered": True})
        conn.commit()
        return {"code": 0, "one_time_password": otp, "expires_in": 1800, "password_change_required": True, "revoked_sessions": sessions}
    finally:
        conn.close()


def owned_media(conn, uid):
    names = set()
    for table, column in (("profiles", "avatar_url"), ("body_cycles", "photo_url"), ("media_uploads", "name")):
        for row in conn.execute("SELECT " + column + " FROM " + table + " WHERE user_id=?", (uid,)):
            if row[0]: names.add(os.path.basename(row[0]))
    for table in ("posts", "comments"):
        for row in conn.execute("SELECT images FROM " + table + " WHERE user_id=?", (uid,)):
            names.update(os.path.basename(n) for n in read_images(row[0]))
    return names


@app.post("/api/media/cleanup")
def retry_media_cleanup(body: dict, actor: str = Depends(actor_of)):
    if body.get("phrase") != "重试注销媒体清理":
        raise HTTPException(409, "请确认重试注销媒体清理")
    conn = db()
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS ops_media_cleanup (name TEXT PRIMARY KEY, created_at TEXT NOT NULL)")
        conn.commit()
        result = cleanup_media(conn)
        audit(actor, "retry_media_cleanup", after=result)
        return result
    finally:
        conn.close()


def cleanup_media(conn):
    # Jobs survive failure; repeated account deletion does not have to recreate them.
    conn.execute("BEGIN IMMEDIATE")
    referenced = set()
    for table, column in (("profiles", "avatar_url"), ("body_cycles", "photo_url"), ("media_uploads", "name"), ("messages", "media_name")):
        referenced.update(os.path.basename(r[0]) for r in conn.execute("SELECT " + column + " FROM " + table) if r[0])
    for table in ("posts", "comments"):
        for row in conn.execute("SELECT images FROM " + table):
            referenced.update(os.path.basename(n) for n in read_images(row[0]))
    done = pending = 0
    for row in conn.execute("SELECT name FROM ops_media_cleanup").fetchall():
        name = row[0]
        if name in referenced:
            pending += 1
            continue
        path = Path(UPLOAD_DIR) / name
        if name != os.path.basename(name) or path.is_symlink() or path.resolve().parent != Path(UPLOAD_DIR).resolve():
            pending += 1
            continue
        try:
            path.unlink(missing_ok=True)
            Path(str(path) + ".thumb.jpg").unlink(missing_ok=True)
            conn.execute("DELETE FROM ops_media_cleanup WHERE name=?", (name,))
            done += 1
        except OSError:
            pending += 1
    conn.commit()
    return {"removed": done, "pending": pending}


@app.post("/api/users/{uid}/delete-account")
def delete_account(uid: int, body: dict, actor: str = Depends(actor_of)):
    plan_only = bool((body or {}).get("plan_only"))
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = _load_user_for_action(conn, uid, (body or {}).get("expect_username"))
        plan, total = [], 0
        for table, col in user_refs(conn):
            if table == "users":
                continue
            try:
                n = conn.execute("SELECT COUNT(*) FROM %s WHERE %s=?" % (table, col), (uid,)).fetchone()[0]
            except sqlite3.Error:
                continue
            if n:
                plan.append({"table": table, "column": col, "rows": n})
                total += n
        dependents = dependent_rows(conn, uid)
        total += sum(item["rows"] for item in dependents)
        if plan_only:
            return {"code": 0, "plan": plan, "dependents": dependents,
                    "tables": len(plan) + len(dependents), "rows": total}
        want = (body or {}).get("confirm_rows")
        if want is None or int(want) != total:
            raise HTTPException(status_code=409,
                                detail="待删行数对不上：服务端算出 %d 行（传回来的是 %r）" % (total, want))
        before = {key: row[key] for key in safe_columns(conn, "users")}
        conn.execute("PRAGMA defer_foreign_keys=ON")
        media = owned_media(conn, uid)
        conn.execute("CREATE TABLE IF NOT EXISTS ops_media_cleanup (name TEXT PRIMARY KEY, created_at TEXT NOT NULL)")
        conn.executemany("INSERT OR IGNORE INTO ops_media_cleanup VALUES (?,?)", [(name, now_iso()) for name in media])
        # 先清别人留在他帖子上的互动，否则这些行会指向马上要删的帖子，外键校验必然失败
        for item in sorted(dependents, key=lambda item: item.get("scope") != "comment"):
            if item.get("scope") == "comment":
                conn.execute("DELETE FROM " + item["table"] + " WHERE comment_id IN (SELECT id FROM comments WHERE user_id=? OR post_id IN (SELECT id FROM posts WHERE user_id=?)) AND user_id<>?", (uid, uid, uid))
            else:
                conn.execute("DELETE FROM %s WHERE %s IN (SELECT id FROM posts WHERE user_id=?) AND user_id<>?" % (item["table"], item["column"]), (uid, uid))
        for item in plan:
            conn.execute("DELETE FROM %s WHERE %s=?" % (item["table"], item["column"]), (uid,))
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        left = conn.execute("PRAGMA foreign_key_check").fetchall()
        if left:
            conn.rollback()
            audit(actor, "delete_account", "users", uid, before=before, after=None,
                  note="外键校验剩 %d 条，整笔已回滚" % len(left))
            raise HTTPException(status_code=500, detail="删除后外键不自洽，整笔回滚，账号还在")
        audit_in(conn, actor, "delete_account", "users", uid, before=before,
              after={"tables": len(plan) + len(dependents), "rows": total,
                     "dependents": dependents}, note="已删")
        conn.commit()
        cleanup = cleanup_media(conn)
        return {"code": 0, "media_cleanup": cleanup, "deleted_tables": len(plan) + len(dependents),
                "deleted_rows": total, "dependents": dependents}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------- 强更门与备份

GATE_READBACK_TIMEOUT = 12.0


def release_check(verify_hash: bool = False) -> dict:
    """当前发布"真的可安装"吗：包在、大小对、包内自报构建号对；抬门时再加 SHA-256。

    清单写着 63 而 web 目录里还是 62 的包，抬门就是把所有人锁在门外。
    所以核的是文件本身，不是清单自己说自己是几。
    """
    out = {"manifest_ok": False, "version_code": 0, "apk_present": False, "apk_size_ok": False,
           "apk_sha_ok": None, "apk_build_ok": False, "installable": False, "reason": ""}
    try:
        with open(os.path.join(WEB_DIR, "version.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
        out["version_code"] = int(manifest.get("version_code") or 0)
        out["manifest_ok"] = out["version_code"] > 0
    except Exception as error:
        out["reason"] = "版本清单读不到：" + type(error).__name__
        return out
    if not out["manifest_ok"]:
        out["reason"] = "版本清单里没有有效 version_code"
        return out
    apk = os.path.join(WEB_DIR, "qingsu.apk")
    if not os.path.isfile(apk):
        out["reason"] = "安装包不在 web 目录"
        return out
    out["apk_present"] = True
    size = os.path.getsize(apk)
    out["apk_size_ok"] = size == int(manifest.get("size") or -1)
    if not out["apk_size_ok"]:
        out["reason"] = "安装包大小与清单不符：磁盘 %d，清单 %s" % (size, manifest.get("size"))
        return out
    if verify_hash:
        digest = hashlib.sha256()
        with open(apk, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        out["apk_sha_ok"] = digest.hexdigest() == str(manifest.get("sha256") or "")
        if not out["apk_sha_ok"]:
            out["reason"] = "安装包 SHA-256 与清单不符"
            return out
    try:
        with zipfile.ZipFile(apk) as archive:
            raw = b""
            for name in archive.namelist():
                if name.endswith("assets/app.js"):
                    raw = archive.read(name)
                    break
    except Exception as error:
        out["reason"] = "安装包读不出包内构建号：" + type(error).__name__
        return out
    out["apk_build_ok"] = ("const APP_BUILD = %d;" % out["version_code"]).encode("utf-8") in raw
    if not out["apk_build_ok"]:
        out["reason"] = "包内 assets/app.js 自报的构建号不是 %d" % out["version_code"]
        return out
    out["installable"] = True
    return out


def write_min_build(value: int) -> None:
    """原子换门文件：唯一临时名 + fsync + replace。

    固定临时名会让两个进程同时抬门时互相踩掉对方正在写的文件，
    写一半被 replace 出去就是一个非数字的门——主应用会静默回落到清单值。

    降权之后本进程写不动 /opt/qingsu/data/min_build，改成 sudo 调 qingsu-set-gate：
    那个 helper 同样走"同目录临时文件 + mv"，并把参数判死成 1~6 位纯数字。
    """
    if GATE_HELPER:
        result = run_privileged("gate", [str(int(value))], lambda: None, timeout=30)
        if result is None or result.get("returncode"):
            raise HTTPException(status_code=503,
                                detail="改门 helper 失败（退出码 %s）：%s"
                                       % ((result or {}).get("returncode"),
                                          ((result or {}).get("stderr") or "").strip()[:200]))
        return
    directory = os.path.dirname(MIN_BUILD_FILE) or "."
    fd, tmp = tempfile.mkstemp(prefix=".min_build.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(str(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, MIN_BUILD_FILE)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def gate_read_back(expect: int, timeout: float = GATE_READBACK_TIMEOUT):
    """以主应用自己报的 min_build 为准，不看本接口有没有返回 200。

    连不上时只试 3 次就撤：主应用真的挂了，等满 12 秒也不会等来答复，
    而抬门接口卡在那里会把运维台的整个"门"卡片拖成转圈。
    """
    deadline = time.time() + timeout
    unreachable = 0
    state = gate_state()
    while not (state["override"] == expect and state["min_build_reported_by_app"] == expect):
        if state["app_error"]:
            unreachable += 1
            if unreachable >= 3:
                return False, state
        if time.time() >= deadline:
            return False, state
        time.sleep(0.4)
        state = gate_state()
    return True, state


def read_min_build():
    """门文件的三种状态要分得开：没有文件（走清单）、有文件但读不出数（坏状态）。
    把后者当成前者，界面会显示"当前门 = 清单值"，而实际主应用回落到清单是另一套日志。"""
    if not os.path.exists(MIN_BUILD_FILE):
        return None, "missing"
    try:
        return int((Path(MIN_BUILD_FILE).read_text() or "0").strip() or 0), "ok"
    except (ValueError, OSError):
        return None, "unreadable"


@contextlib.contextmanager
def gate_lock():
    """抬门的互斥借业务库写锁：BEGIN IMMEDIATE 拿到就是独占，进程崩了也自动释放。

    不用"固定名临时文件当锁"——那种锁崩一次就留下一把死的，而且它和真正要保护的
    门文件不在同一个原子域里。审计必须放在锁外：audit() 自己开连接写库，
    在 RESERVED 锁里等 5 秒只会把抬门请求变成 database is locked。
    """
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def gate_state() -> dict:
    manifest_min, manifest_code, manifest_err = None, None, ""
    try:
        with open(os.path.join(WEB_DIR, "version.json"), encoding="utf-8") as handle:
            data = json.load(handle)
        manifest_min = int(data.get("min_version_code") or 0)
        manifest_code = int(data.get("version_code") or 0)
    except Exception as e:
        manifest_err = type(e).__name__
    override, override_status = read_min_build()
    ready, err = json_get(APP_API + "/health/ready")
    gate = (ready or {}).get("gate") or {}
    return {"override": override, "manifest_min": manifest_min, "manifest_code": manifest_code,
            "override_status": override_status,
            "manifest_error": manifest_err,
            "effective": override if override is not None else (manifest_min or 0),
            "brake_on": override == 0,
            "seen_builds": gate.get("builds"),
            "blocked_since_restart": gate.get("blocked"),
            "min_build_reported_by_app": (ready or {}).get("min_build"),
            "app_error": err}


@app.get("/api/gate")
def gate_get(actor: str = Depends(actor_of)):
    out = gate_state()
    out["release"] = release_check()
    out["note"] = ("seen_builds 只覆盖主应用自上次重启以来见过的构建号，不是装机总量；"
                   "抬门前先看这个数和被挡计数，别把它当用户总量。"
                   "release.installable 为假时抬门会被拒绝——门抬到装不上的版本，用户连升级都升不了")
    return out


@app.post("/api/gate")
def gate_set(body: dict, actor: str = Depends(actor_of)):
    try:
        expect = int((body or {}).get("expect_current"))
        new = int((body or {}).get("new"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="expect_current 与 new 都要是整数")
    if new <= 0:
        raise HTTPException(status_code=400, detail="抬到 0 等于放开所有人，那要走刹车按钮，不走抬门")
    release = release_check(verify_hash=True)
    if not release["installable"]:
        audit(actor, "raise_gate_refused", "config", "min_build", after={"new": new},
              note=release["reason"])
        raise HTTPException(status_code=409, detail="抬门已拒绝：%s" % release["reason"])
    if new > release["version_code"]:
        raise HTTPException(status_code=400,
                            detail="最低版本不能超过已发布且可安装的版本 %d" % release["version_code"])
    try:
        with gate_lock():
            current, status = read_min_build()
            if status == "unreadable":
                raise HTTPException(status_code=409,
                                    detail="门文件读不出数字，先修文件再抬门（现在抬等于盲改）")
            if status == "missing":
                raise HTTPException(status_code=409,
                                    detail="现在没有运维刹车文件，先建一个再抬门（别拿清单值当 current）")
            if expect != current:
                raise HTTPException(status_code=409,
                                    detail="当前门是 %s，你以为是 %s——没改" % (current, expect))
            if new < current:
                raise HTTPException(status_code=400, detail="门只能往上抬，往下放要走人工确认流程")
            write_min_build(new)
    except sqlite3.OperationalError:
        raise HTTPException(status_code=409, detail="另一次抬门正在进行，稍后再试")
    confirmed, after = gate_read_back(new)
    reported = (after or {}).get("min_build_reported_by_app")
    app_error = (after or {}).get("app_error")
    if not confirmed:
        if app_error or reported is None:
            # 主应用联系不上：门文件已经写对，但没人能证明它生效。
            # 这既不是"成功生效"，也不该回退——回退会把一次正常的抬门变成
            # "悄悄没改"，而现场只会看到门还是旧值。
            audit(actor, "raise_gate_unconfirmed", "config", "min_build",
                  before={"min_build": current},
                  after={"min_build": (after or {}).get("override"),
                         "reported_by_app": reported,
                         "effective": (after or {}).get("effective")},
                  note="门文件已写成 %d，但主应用没答话（%s）：生效与否以 /health/ready 为准"
                       % (new, app_error or "min_build 为空"))
            return {"code": 0, "written": new, "confirmed": False,
                    "effective_now": (after or {}).get("effective"),
                    "reported_by_app": reported,
                    "app_error": app_error or "unreachable",
                    "blocked_now": (after or {}).get("blocked_since_restart"),
                    "note": "没拿到主应用回读，不能说已生效：等它能答话后再看一次 /api/gate"}
        with gate_lock():
            if read_min_build()[0] == new:
                write_min_build(current)
        restored, final = gate_read_back(current, timeout=6.0)
        audit(actor, "raise_gate_reverted", "config", "min_build",
              before={"min_build": current, "attempted": new},
              after={"min_build": (final or {}).get("override"),
                     "reported_by_app": reported,
                     "restored_reported_by_app": (final or {}).get("min_build_reported_by_app")},
              note="主应用回读到的是 %r，不是 %d；已回退%s"
                   % (reported, new, "并确认" if restored else "但仍未确认生效"))
        raise HTTPException(
            status_code=503,
            detail="门写进去了，但主应用回读到的最低版本是 %r，不是 %d——已回退到 %s%s" % (
                reported, new, current, "" if restored else "（回退同样没确认，请人工核对 /health/ready）"))
    audit(actor, "raise_gate", "config", "min_build", before={"min_build": current},
          after={"min_build": new, "effective": after["effective"],
                 "reported_by_app": after["min_build_reported_by_app"],
                 "release_version": release["version_code"]})
    return {"code": 0, "written": new, "effective_now": after["effective"],
            "reported_by_app": after["min_build_reported_by_app"],
            "blocked_now": after["blocked_since_restart"],
            "installable_verified": True,
            "note": "门有没有生效，以主应用 /health/ready 的 min_build 为准，不看本接口返回 200"}


@app.post("/api/brake")
def gate_brake(body: dict, actor: str = Depends(actor_of)):
    """刹车：把门写成 0。放错方向的门风险不对称，所以单独一个动作、单独一次确认。"""
    state = gate_state()
    if str((body or {}).get("phrase") or "").strip() != "放开全部客户端":
        raise HTTPException(status_code=409, detail="要把门放开，必须原样带回确认短语")
    try:
        with gate_lock():
            write_min_build(0)
    except sqlite3.OperationalError:
        raise HTTPException(status_code=409, detail="另一次门操作正在进行，稍后再试")
    confirmed, after = gate_read_back(0, timeout=6.0)
    audit(actor, "gate_brake", "config", "min_build", before={"min_build": state["override"]},
          after={"min_build": 0, "effective": (after or {}).get("effective"),
                 "reported_by_app": (after or {}).get("min_build_reported_by_app"),
                 "confirmed": confirmed})
    return {"code": 0, "effective_now": (after or {}).get("effective"),
            "reported_by_app": (after or {}).get("min_build_reported_by_app"),
            "confirmed_by_app": confirmed}


_LONG_TASKS = None
_LONG_TASK_BUSY = RuntimeError


def long_tasks():
    """长任务表由主应用的 app_modules.long_tasks 拥有（方案 C05：一张表一个所有者）。

    后台不自己 CREATE 这张表，也不自己写状态机——那会变成"两处都能改任务"，
    而任务状态恰恰是"界面报错了但后台其实改完了"这类事故的落点。
    """
    global _LONG_TASKS, _LONG_TASK_BUSY
    if _LONG_TASKS is not None:
        return _LONG_TASKS
    root = os.environ.get("QINGSU_APP_ROOT", "/opt/qingsu")
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from app_modules.long_tasks import LongTasks, LongTaskBusy
    except ImportError as error:
        raise HTTPException(status_code=503,
                            detail="读不到主应用的任务模块（%s）：异步备份/长任务用不了，"
                                   "同步那条路照旧" % type(error).__name__)
    _LONG_TASK_BUSY = LongTaskBusy
    _LONG_TASKS = LongTasks(DB_PATH)
    return _LONG_TASKS


def backup_now(actor: str, body: dict):
    """同步跑一次备份并校验（原来 /api/backup 的全部行为）。"""
    def list_backups():
        """降权后备份目录（root:700）本进程可能列不出来。列不出来不等于没有备份，
        所以这里只回报"看不看得见"，不把空集合当成"一个都没有"。"""
        try:
            return set(os.listdir(BACKUP_DIR)), True
        except FileNotFoundError:
            return set(), True
        except OSError:
            return set(), False

    before, listing_visible = list_backups()
    try:
        def direct_backup():
            proc = subprocess.run([PYTHON_BIN, BACKUP_SCRIPT], capture_output=True, text=True, timeout=600)
            return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
        proc = run_privileged("backup", [], direct_backup)
    except subprocess.TimeoutExpired:
        audit(actor, "backup", "config", "backup", after=None, note="超时 600s")
        raise HTTPException(status_code=500, detail="备份超时")
    except Exception as e:
        audit(actor, "backup", "config", "backup", after=None, note="起不来 " + type(e).__name__)
        raise HTTPException(status_code=500, detail="备份脚本起不来")
    if proc["returncode"] != 0:
        audit(actor, "backup", "config", "backup", after=None,
              note="脚本退出码 %d" % proc["returncode"])
        raise HTTPException(status_code=500,
                            detail="备份失败（退出码 %d）：%s"
                                   % (proc["returncode"],
                                      (proc["stderr"] or proc["stdout"] or "")[-400:]))
    # 降权后备份目录是 root:700，本进程列不出来：列不出就说列不出，
    # 不能把"没看到新快照"当成"备份没做"，也不能反过来当成"做了"。
    after_listing, still_visible = list_backups()
    listing_visible = listing_visible and still_visible
    fresh = sorted(after_listing - before)
    snapshot = next((f for f in fresh if f.startswith("qingsu-") and f.endswith(".db")), None)
    check = "no_snapshot"
    if snapshot:
        try:
            snap = sqlite3.connect("file:%s?mode=ro" % Path(BACKUP_DIR, snapshot).as_posix(),
                                  uri=True, timeout=5)
            check = snap.execute("PRAGMA integrity_check").fetchone()[0]
            snap.close()
        except sqlite3.Error as e:
            check = "error_" + type(e).__name__
    elif not listing_visible:
        # 降权后备份目录本进程读不到，改读 backup.py 自己打的那行 JSON：
        # 它内部已经跑过 integrity_check，不是 ok 就直接抛错、退出码非零。
        try:
            reported = json.loads((proc["stdout"] or "").strip().splitlines()[-1])
            snapshot = str(reported.get("backup") or "unknown")
            check = "ok" if reported.get("integrity") == "ok" else str(reported.get("integrity"))
        except (IndexError, ValueError):
            check = "helper_printed_nothing_verifiable"
    audit(actor, "backup", "config", snapshot or "none", after={"integrity": check},
          note="新增 %d 个文件%s" % (len(fresh), "" if listing_visible else "（目录本进程不可读，校验取自脚本输出）"))
    if check != "ok":
        raise HTTPException(status_code=500, detail="备份出来了但校验不是 ok：%s" % check)
    return {"code": 0, "snapshot": snapshot, "integrity": check, "new_files": len(fresh),
            "directory_readable": listing_visible}


def run_backup_task(task_id: str, actor: str) -> dict:
    """跑一份备份并把结果写进任务表。单独成函数是为了判据能直接调它，
    而不是在测试里另抄一遍"失败了会标成什么"——那等于没测产品代码。"""
    store = long_tasks()
    if not store.claim(task_id, actor):
        return {"claimed": False}
    try:
        result = backup_now(actor, {})
        store.finish(task_id, result)
        return {"claimed": True, "status": "done"}
    except HTTPException as error:
        store.fail(task_id, {"detail": error.detail, "status": error.status_code}, retryable=True)
        return {"claimed": True, "status": "failed"}
    except Exception as error:
        store.fail(task_id, {"detail": type(error).__name__}, retryable=True)
        return {"claimed": True, "status": "failed"}


def _spawn_backup_task(task_id: str, actor: str) -> None:
    """后台线程里跑那份最长 600 秒的活，结果落在任务表里，浏览器关掉也不会丢。"""
    import threading
    threading.Thread(target=run_backup_task, args=(task_id, actor), daemon=True).start()


@app.post("/api/backup")
def backup(body: dict, actor: str = Depends(actor_of)):
    """跑主应用自己的 backup.py，并且读回快照做 integrity_check 才算成功。
    只看脚本退出码不够——备份写出来了但库是坏的，退出码照样是 0。

    `{"async": true}` 走持久任务：立刻回一个任务号，进度和结果用 /api/backup/{id} 查。
    默认仍然同步，因为现有判据与运维页都在等真结果——异步是加出来的能力，不是换掉的行为。
    """
    if (body or {}).get("async"):
        store = long_tasks()
        try:
            # dedup_key 让"同一操作者连点两下"拿到同一个任务号；
            # 判据钉的就是这个可观测事实（两次返回的 id 相同），不去猜什么 reused 标记。
            task = store.enqueue("backup", args={}, owner=actor,
                                 dedup_key="backup:" + actor, max_active=1)
        except _LONG_TASK_BUSY as busy:
            raise HTTPException(status_code=409, detail=str(busy))
        if task["status"] in ("pending", "interrupted"):
            _spawn_backup_task(task["id"], actor)
        audit(actor, "backup_queued", "config", task["id"], after={"status": task["status"]})
        return {"code": 0, "task_id": task["id"], "status": task["status"],
                "note": "任务号请留在工单里；关掉本页不影响它跑完"}
    return backup_now(actor, body)


@app.get("/api/backup/{task_id}")
def backup_status(task_id: str, actor: str = Depends(actor_of)):
    store = long_tasks()
    task = store.status(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="没有这个任务号")
    return {"code": 0, "task": task}


def _read_mail():
    try:
        raw = json.loads(Path(MAIL_CONFIG).read_text(encoding='utf-8'))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _mail_safe(raw):
    return {k: raw.get(k, '') for k in ('host', 'port', 'user', 'from', 'tls')} | {
        'enabled': raw.get('enabled', bool(raw)), 'password_set': bool(raw.get('password')),
        'configured': bool(all(raw.get(k) for k in ('host', 'user', 'password', 'from')))}


def _write_private(path, value, app_read=False):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=target.name + '.', dir=target.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        if os.name == 'posix':
            if app_read and os.geteuid() == 0:
                import grp
                os.chown(temp, 0, grp.getgrnam('qingsu').gr_gid)
            os.chmod(temp, 0o640 if app_read else 0o600)
        os.replace(temp, target)
    finally:
        Path(temp).unlink(missing_ok=True)


@app.get('/api/mail')
def mail_status(actor: str = Depends(actor_of)):
    raw = _read_mail()
    check = None
    try:
        check = json.loads(Path(MAIL_CHECK).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        pass
    live, error = json_get(APP_API + '/api/account/recovery-status')
    return {'config': _mail_safe(raw), 'check': check, 'live': live or {'unreachable': error}}


@app.post('/api/mail')
def mail_save(body: dict, actor: str = Depends(actor_of)):
    before = _read_mail()
    enabled = body.get('enabled', True)
    if not isinstance(enabled, bool):
        raise HTTPException(400, '启用状态无效')
    if not enabled:
        after = dict(before, enabled=False)
    else:
        host = str(body.get('host', '')).strip().lower()
        user = str(body.get('user', '')).strip()
        sender = str(body.get('from', '')).strip()
        mode = str(body.get('tls', 'ssl'))
        try:
            port = int(body.get('port', 465))
        except (TypeError, ValueError):
            raise HTTPException(400, 'SMTP端口无效')
        import re
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host) or '.' not in host or host.endswith('.local'):
            raise HTTPException(400, '请填写公开SMTP服务域名')
        if mode not in ('ssl', 'starttls') or port not in (465, 587):
            raise HTTPException(400, '仅支持465端口SSL或587端口STARTTLS')
        if (mode == 'ssl') != (port == 465):
            raise HTTPException(400, '端口与加密方式不匹配')
        if not user or len(user) > 254 or any(ch in user + sender for ch in '\r\n') or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', sender):
            raise HTTPException(400, '发信账号或发件邮箱无效')
        password = body.get('password', '')
        if not isinstance(password, str) or len(password) > 1024:
            raise HTTPException(400, '授权码格式无效')
        if not password and host == before.get('host') and user == before.get('user'):
            password = before.get('password', '')
        if not password:
            raise HTTPException(400, '请填写SMTP密码或授权码')
        after = dict(host=host, port=port, user=user, password=password, tls=mode, enabled=True)
        after['from'] = sender
    _write_private(MAIL_CONFIG, after, app_read=True)
    Path(MAIL_CHECK).unlink(missing_ok=True)
    audit(actor, 'mail_config', 'config', 'mail', before={'configured': bool(before)}, after={'enabled': enabled, 'configured': bool(after.get('password'))})
    return {'code': 0, 'config': _mail_safe(after), 'note': '配置已保存；连接检查通过也不代表实际邮件已投递'}


_mail_check_at = 0.0


def _check_smtp(raw):
    addresses = socket.getaddrinfo(raw['host'], raw['port'], type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
        raise ValueError('SMTP service must use public addresses')
    context = ssl.create_default_context()
    if raw['tls'] == 'ssl':
        smtp = smtplib.SMTP_SSL(raw['host'], raw['port'], timeout=8, context=context)
    else:
        smtp = smtplib.SMTP(raw['host'], raw['port'], timeout=8)
    try:
        if raw['tls'] == 'starttls':
            smtp.starttls(context=context)
        smtp.login(raw['user'], raw['password'])
    finally:
        smtp.quit()


@app.post('/api/mail/check')
def mail_check(actor: str = Depends(actor_of)):
    global _mail_check_at
    raw = _read_mail()
    if not _mail_safe(raw)['configured'] or not raw.get('enabled', True):
        raise HTTPException(400, '请先保存并启用发信配置')
    if time.monotonic() - _mail_check_at < 30:
        raise HTTPException(429, '请等30秒再检查')
    _mail_check_at = time.monotonic()
    result = {'checked_at': now_iso(), 'ok': False, 'delivery_tested': False}
    try:
        _check_smtp(raw)
        result.update(ok=True, message='TLS连接及账号认证通过；尚未验证邮件投递')
    except Exception as error:
        result['message'] = '连接或认证失败（' + type(error).__name__ + '）'
    _write_private(MAIL_CHECK, result)
    audit(actor, 'mail_check', 'config', 'mail', after={'ok': result['ok']})
    return result


@app.get('/api/site-status')
def site_status(actor: str = Depends(actor_of)):
    active, active_error = json_get(APP_API + '/health/ready', timeout=4)
    base = (active or {}).get('site_base') or 'https://124.220.54.64'
    if base not in ('https://124.220.54.64', 'https://scientificexploration.art'):
        base = 'https://124.220.54.64'
    ready, error = json_get(base + '/health/ready', timeout=4)
    version, version_error = json_get(base + '/version.json', timeout=4)
    domain_ready, domain_error = json_get('https://scientificexploration.art/health/ready', timeout=4) if base != 'https://scientificexploration.art' else (ready, error)
    certificates = []
    for host in ('scientificexploration.art', '124.220.54.64'):
        path = '/etc/letsencrypt/live/' + host + '/cert.pem'
        try:
            p = subprocess.run(['openssl', 'x509', '-noout', '-enddate', '-in', path], capture_output=True, text=True, timeout=3)
            from email.utils import parsedate_to_datetime
            left = round((parsedate_to_datetime(p.stdout.strip().split('=', 1)[1]).timestamp() - time.time()) / 3600, 1)
            certificates.append({'host': host, 'hours_left': left})
        except Exception:
            certificates.append({'host': host, 'hours_left': None})
    monitor = None
    try:
        raw = json.loads(Path(MONITOR_FILE).read_text())
        monitor = {k: raw.get(k) for k in ('checked_at', 'ready', 'free_disk_mb', 'backup_age_hours', 'certificate_hours_left', 'errors_5xx', 'p95_ms', 'problems')}
    except (OSError, ValueError):
        pass
    try:
        timer = subprocess.run(['systemctl', 'is-active', 'qingsu-push.timer'], capture_output=True, text=True, timeout=3).stdout.strip()
    except OSError:
        timer = 'unknown'
    c = db(readonly=True)
    try:
        try:
            push_count = c.execute('SELECT COUNT(*) FROM push_subscriptions').fetchone()[0]
        except sqlite3.Error:
            push_count = None
    finally:
        c.close()
    return {'base': base, 'https_ok': ready is not None, 'error': error, 'site_base': (ready or {}).get('site_base'),
            'planned_domain': 'https://scientificexploration.art', 'domain_https_ok': domain_ready is not None, 'domain_error': domain_error,
            'release': (ready or {}).get('release'), 'version': {k: (version or {}).get(k) for k in ('version_code', 'version_name', 'apk_url')},
            'version_error': version_error, 'certificates': certificates, 'monitor': monitor,
            'push': {'timer': timer, 'subscriptions': push_count}, 'checked_at': now_iso()}


@app.get("/")
def console():
    if not CONSOLE_HTML.is_file():
        raise HTTPException(status_code=404, detail="运维页没随包发布")
    return FileResponse(CONSOLE_HTML, media_type="text/html; charset=utf-8")
