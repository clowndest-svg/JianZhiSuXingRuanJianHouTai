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
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
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
SESSION_TTL = 8 * 3600
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
}


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


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


def safe_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """该表能对外出现的列：真实结构减去敏感清单。
    不写死列清单——以后谁往表里加一列敏感字段，默认是"看不见"，不是"漏出去"。"""
    return [c for c in columns(conn, table) if (table, c) not in SENSITIVE]


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


def make_session(actor: str) -> str:
    payload = "%s|%d" % (actor, int(time.time()) + SESSION_TTL)
    return "%s.%s" % (payload, _sign(payload))


def read_session(raw: str) -> str | None:
    if not raw or "." not in raw:
        return None
    payload, sig = raw.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    try:
        actor, exp = payload.rsplit("|", 1)
        if int(exp) < int(time.time()):
            return None
    except ValueError:
        return None
    return actor


def actor_of(request: Request,
             x_qingsu_token: str | None = Header(None),
             authorization: str | None = Header(None)) -> str:
    """应用层的身份（L3）。注意令牌走 X-Qingsu-Token 而不是 Authorization: Bearer：
    Authorization 这一格已经被 L2 的 Basic 占了，两个方案不能共用同一个头。"""
    token, _ = load_secrets()
    supplied = (x_qingsu_token or "").strip()
    if not supplied and authorization and authorization.startswith("Token "):
        supplied = authorization[6:].strip()
    if supplied and hmac.compare_digest(supplied, token):
        return "script"
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
    user, password = basic_gate()
    challenge = 'Basic realm="qingsu-ops", charset="UTF-8"'
    if not password:
        return JSONResponse({"detail": "后台 Basic 口令未配置"}, status_code=503,
                            headers={"WWW-Authenticate": challenge})
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        try:
            raw = base64.b64decode(header[6:].strip()).decode("utf-8")
            got_user, _, got_password = raw.partition(":")
            if hmac.compare_digest(got_user, user) and hmac.compare_digest(got_password, password):
                return await call_next(request)
        except Exception:
            pass    # 解不开就等于没授权，不区分原因，免得给探测留差异信号
    return JSONResponse({"detail": "需要后台 Basic 口令"}, status_code=401,
                        headers={"WWW-Authenticate": challenge})


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
    ok = bool(supplied) and hmac.compare_digest(supplied, token)
    if not ok:
        locked = hits + 1 >= LOGIN_MAX_ATTEMPTS
        _attempts[ip] = (hits + 1, time.time() + LOGIN_LOCK_SEC if locked else 0.0)
        audit("anonymous", "login_failed", "ip", ip, note="第 %d 次" % (hits + 1))
        raise HTTPException(status_code=401, detail="运维令牌不对")
    _attempts.pop(ip, None)
    response.set_cookie("qops", make_session("console"), max_age=SESSION_TTL,
                        httponly=True, samesite="strict",
                        secure=os.environ.get("OPS_INSECURE_COOKIE") != "1", path="/")
    return {"code": 0, "expires_in": SESSION_TTL}


@app.post("/api/logout")
def logout(response: Response, actor: str = Depends(actor_of)):
    response.delete_cookie("qops", path="/")
    return {"code": 0}


@app.get("/api/whoami")
def whoami(actor: str = Depends(actor_of)):
    return {"actor": actor, "at": now_iso()}


# ---------------------------------------------------------------- 只读


@app.get("/api/health")
def health(actor: str = Depends(actor_of)):
    ready, ready_err = json_get(APP_API + "/health/ready")
    container = "unknown"
    try:
        proc = subprocess.run(["docker", "inspect", "-f",
                               "{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}",
                               CONTAINER_NAME], capture_output=True, text=True, timeout=8)
        container = (proc.stdout or proc.stderr).strip() or "unknown"
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
    backups = sorted(os.listdir(BACKUP_DIR))[-3:] if os.path.isdir(BACKUP_DIR) else []
    return {"app": ready if ready is not None else {"unreachable": ready_err},
            "console_container": container,
            "disk_free_mb": disk.free // 1024 // 1024,
            "mem_mb": mem, "recent_backups": backups, "ops_time": now_iso()}


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
            "reports_open": counts["content_reports"],
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


@app.get("/api/users")
def list_users(q: str = "", limit: int = 20, actor: str = Depends(actor_of)):
    """运营页要先"找得到人"才谈得上封号。只出白名单列，且只读。
    （Directus 那边是另一套登录，不在这个页面里代跳。）"""
    limit = max(1, min(int(limit or 20), 50))
    conn = db(readonly=True)
    try:
        cols = ",".join(safe_columns(conn, "users"))
        term = str(q or "").strip()[:60]
        if term:
            like = "%" + term + "%"
            rows = conn.execute(
                "SELECT %s FROM users WHERE CAST(id AS TEXT)=? OR username LIKE ? "
                "OR nickname LIKE ? OR public_id LIKE ? ORDER BY id DESC LIMIT ?" % cols,
                (term, like, like, like, limit)).fetchall()
        else:
            rows = conn.execute("SELECT %s FROM users ORDER BY id DESC LIMIT ?" % cols,
                                (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["sessions"] = conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?",
                                         (d["id"],)).fetchone()[0]
            out.append(d)
        return {"items": out, "count": len(out), "query": term}
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
                rows = conn.execute("SELECT %s FROM %s WHERE %s=?" % (want, table, col),
                                    (uid,)).fetchall()
            except sqlite3.Error:
                continue
            if rows:
                out["tables"].setdefault(table, [])
                out["tables"][table].extend([_redact_table(table, dict(r)) for r in rows])
        out["actor"] = actor
        out["exported_at"] = now_iso()
        return out
    finally:
        conn.close()


def _redact_table(table: str, row: dict) -> dict:
    return {k: v for k, v in row.items() if (table, k) not in SENSITIVE}


@app.get("/api/audit")
def audit_list(limit: int = 40, actor: str = Depends(actor_of)):
    limit = max(1, min(int(limit or 40), 200))
    conn = db(readonly=True)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM admin_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
    finally:
        conn.close()
    for r in rows:
        for key in ("before_json", "after_json"):
            try:
                payload = json.loads(r[key]) if r[key] else None
            except json.JSONDecodeError:
                payload = "非JSON(截断)"
            if isinstance(payload, dict):
                r[key] = _redact_table(str(r.get("target_kind") or ""), payload)
            r[key] = payload
    return {"items": rows}


# ---------------------------------------------------------------- 高危


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
        conn.commit()
        audit(actor, "ban", "users", uid, before=before,
              after={"banned_at": stamp, "ban_reason": reason})
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
        conn.commit()
        audit(actor, "unban", "users", uid, before=before,
              after={"banned_at": None, "ban_reason": ""})
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
        conn.commit()
        audit(actor, "revoke_sessions", "users", uid, before={"sessions": n}, after={"sessions": 0})
        return {"code": 0, "revoked": n}
    finally:
        conn.close()


@app.post("/api/users/{uid}/reset-password")
def reset_password(uid: int, body: dict, actor: str = Depends(actor_of)):
    """改口令必须连带撤销全部会话：否则旧 token 在新口令之下仍然可用，
    "我给她换了密码所以踢掉了登录"就是句假话。"""
    conn = db()
    try:
        row = _load_user_for_action(conn, uid, (body or {}).get("expect_username"))
        otp = gen_otp_password()
        salt, pw_hash = make_pw(otp)
        sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (uid,)).fetchone()[0]
        conn.execute("UPDATE users SET password_hash=?, pw_salt=? WHERE id=?", (pw_hash, salt, uid))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        conn.commit()
        # 一次性口令本身不落库、不进日志，只在响应里出现一次
        audit(actor, "reset_pw", "users", uid,
              before={"username": row["username"], "sessions": sessions},
              after={"sessions": 0, "otp_delivered": True})
        return {"code": 0, "one_time_password": otp, "revoked_sessions": sessions}
    finally:
        conn.close()


@app.post("/api/users/{uid}/delete-account")
def delete_account(uid: int, body: dict, actor: str = Depends(actor_of)):
    plan_only = bool((body or {}).get("plan_only"))
    conn = db()
    try:
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
        if plan_only:
            return {"code": 0, "plan": plan, "tables": len(plan), "rows": total}
        want = (body or {}).get("confirm_rows")
        if want is None or int(want) != total:
            raise HTTPException(status_code=409,
                                detail="待删行数对不上：服务端算出 %d 行（传回来的是 %r）" % (total, want))
        before = _redact_table("users", dict(row))
        conn.commit()
        conn.isolation_level = None        # 手动管事务：默认模式下 sqlite3 会自己BEGIN，撞车
        conn.execute("PRAGMA defer_foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        for item in plan:
            conn.execute("DELETE FROM %s WHERE %s=?" % (item["table"], item["column"]), (uid,))
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        left = conn.execute("PRAGMA foreign_key_check").fetchall()
        if left:
            conn.execute("ROLLBACK")
            audit(actor, "delete_account", "users", uid, before=before, after=None,
                  note="外键校验剩 %d 条，整笔已回滚" % len(left))
            raise HTTPException(status_code=500, detail="删除后外键不自洽，整笔回滚，账号还在")
        conn.execute("COMMIT")
        audit(actor, "delete_account", "users", uid, before=before,
              after={"tables": len(plan), "rows": total}, note="已删")
        return {"code": 0, "deleted_tables": len(plan), "deleted_rows": total}
    except HTTPException:
        try:
            if conn.isolation_level is None:
                conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------- 强更门与备份


def gate_state() -> dict:
    manifest_min, manifest_code, manifest_err = None, None, ""
    try:
        with open(os.path.join(WEB_DIR, "version.json"), encoding="utf-8") as handle:
            data = json.load(handle)
        manifest_min = int(data.get("min_version_code") or 0)
        manifest_code = int(data.get("version_code") or 0)
    except Exception as e:
        manifest_err = type(e).__name__
    override = None
    if os.path.exists(MIN_BUILD_FILE):
        try:
            override = int((Path(MIN_BUILD_FILE).read_text() or "0").strip() or 0)
        except ValueError:
            override = None
    ready, err = json_get(APP_API + "/health/ready")
    gate = (ready or {}).get("gate") or {}
    return {"override": override, "manifest_min": manifest_min, "manifest_code": manifest_code,
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
    out["note"] = ("seen_builds 只覆盖主应用自上次重启以来见过的构建号，不是装机总量；"
                   "抬门前先看这个数和被挡计数，别把它当用户总量")
    return out


@app.post("/api/gate")
def gate_set(body: dict, actor: str = Depends(actor_of)):
    state = gate_state()
    current = state["override"]
    try:
        expect = int((body or {}).get("expect_current"))
        new = int((body or {}).get("new"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="expect_current 与 new 都要是整数")
    if current is None:
        raise HTTPException(status_code=409,
                            detail="现在没有运维刹车文件，先建一个再抬门（别拿清单值当 current）")
    if expect != current:
        raise HTTPException(status_code=409, detail="当前门是 %s，你以为是 %s——没改" % (current, expect))
    if new < current:
        raise HTTPException(status_code=400, detail="门只能往上抬，往下放要走人工确认流程")
    if new <= 0:
        raise HTTPException(status_code=400, detail="抬到 0 等于放开所有人，那要走刹车按钮，不走抬门")
    tmp = MIN_BUILD_FILE + ".new"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(str(new))
    os.replace(tmp, MIN_BUILD_FILE)
    after = gate_state()
    audit(actor, "raise_gate", "config", "min_build", before={"min_build": current},
          after={"min_build": new, "effective": after["effective"],
                 "reported_by_app": after["min_build_reported_by_app"]})
    return {"code": 0, "written": new, "effective_now": after["effective"],
            "reported_by_app": after["min_build_reported_by_app"],
            "blocked_now": after["blocked_since_restart"],
            "note": "门有没有生效，以主应用 /health/ready 的 min_build 为准，不看本接口返回 200"}


@app.post("/api/brake")
def gate_brake(body: dict, actor: str = Depends(actor_of)):
    """刹车：把门写成 0。放错方向的门风险不对称，所以单独一个动作、单独一次确认。"""
    state = gate_state()
    if str((body or {}).get("phrase") or "").strip() != "放开全部客户端":
        raise HTTPException(status_code=409, detail="要把门放开，必须原样带回确认短语")
    tmp = MIN_BUILD_FILE + ".new"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write("0")
    os.replace(tmp, MIN_BUILD_FILE)
    after = gate_state()
    audit(actor, "gate_brake", "config", "min_build", before={"min_build": state["override"]},
          after={"min_build": 0, "effective": after["effective"]})
    return {"code": 0, "effective_now": after["effective"],
            "reported_by_app": after["min_build_reported_by_app"]}


@app.post("/api/backup")
def backup(body: dict, actor: str = Depends(actor_of)):
    """跑主应用自己的 backup.py，并且读回快照做 integrity_check 才算成功。
    只看脚本退出码不够——备份写出来了但库是坏的，退出码照样是 0。"""
    before = set(os.listdir(BACKUP_DIR)) if os.path.isdir(BACKUP_DIR) else set()
    try:
        proc = subprocess.run([PYTHON_BIN, BACKUP_SCRIPT], capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        audit(actor, "backup", "config", "backup", after=None, note="超时 600s")
        raise HTTPException(status_code=500, detail="备份超时")
    except Exception as e:
        audit(actor, "backup", "config", "backup", after=None, note="起不来 " + type(e).__name__)
        raise HTTPException(status_code=500, detail="备份脚本起不来")
    if proc.returncode != 0:
        audit(actor, "backup", "config", "backup", after=None,
              note="脚本退出码 %d" % proc.returncode)
        raise HTTPException(status_code=500, detail="备份脚本失败（退出码 %d）" % proc.returncode)
    fresh = sorted((set(os.listdir(BACKUP_DIR)) if os.path.isdir(BACKUP_DIR) else set()) - before)
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
    audit(actor, "backup", "config", snapshot or "none", after={"integrity": check},
          note="新增 %d 个文件" % len(fresh))
    if check != "ok":
        raise HTTPException(status_code=500, detail="备份出来了但校验不是 ok：%s" % check)
    return {"code": 0, "snapshot": snapshot, "integrity": check, "new_files": len(fresh)}


@app.get("/")
def console():
    if not CONSOLE_HTML.is_file():
        raise HTTPException(status_code=404, detail="运维页没随包发布")
    return FileResponse(CONSOLE_HTML, media_type="text/html; charset=utf-8")
