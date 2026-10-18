"""线上封号自证（P 档，一次性夹具，跑完按 id 删干净）。"""
"""线上封号自证（P 档）：用一个一次性夹具账号，跑完按 id 显式删干净。
判据不是"接口返回了 200"，而是主应用自己 403、口令错时不泄露封号状态、解封后恢复。"""
import json, os, secrets, sqlite3, urllib.error, urllib.request

BASE = os.environ.get("QINGSU_LOCAL_API", "http://172.17.0.1:8000")
DB = os.environ.get("QINGSU_DB_PATH", "/opt/qingsu/data/qingsu.db")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
build = str(json.load(opener.open(BASE + "/version.json", timeout=15)).get("version_code") or 0)
assert build != "0", "线上清单没有 version_code"
user = "houkoucheck_" + secrets.token_hex(4)
pw = secrets.token_urlsafe(18)
results = []


def api(path, body=None, token=None, method=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    headers["X-App-Build"] = build
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method or
                                 ("POST" if body is not None else "GET"))
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}


def sql(query, args=(), write=False):
    conn = sqlite3.connect(DB, timeout=5)
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        cur = conn.execute(query, args)
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()] if cur.description else []
        if write:
            conn.commit()
        return rows
    finally:
        conn.close()


before_counts = {}
for t in [r["name"] for r in sql("SELECT name FROM sqlite_master WHERE type='table' "
                                 "AND name NOT LIKE 'sqlite_%'")]:
    before_counts[t] = sql("SELECT COUNT(*) AS c FROM %s" % t)[0]["c"]

st, signup = api("/api/register", {"username": user, "password": pw, "age": 30, "height": 170,
                                   "weight_jin": 160, "target_weight_jin": 140})
uid = signup.get("id")
token = signup.get("token")
results.append(("夹具注册成功", st == 200 and uid and token, "id=%s" % uid))

st, d = api("/api/dashboard", token=token)
results.append(("封号之前一切正常", st == 200, str(st)))

sql("UPDATE users SET banned_at=?, ban_reason=? WHERE id=?", ("2026-10-18T21:00:00", "线上自证", uid), True)
st, d = api("/api/dashboard", token=token)
results.append(("封号之后主应用 403", st == 403, str(st)))
results.append(("403 带机器码 account_banned", d.get("code") == "account_banned", json.dumps(d, ensure_ascii=False)[:120]))
results.append(("封号原因带到了用户端", "线上自证" in str(d.get("detail")), str(d.get("detail"))[:60]))

st, wrong = api("/api/login", {"username": user, "password": "错的口令"})
results.append(("密码错时不泄露封号状态", st == 400 and "停用" not in json.dumps(wrong, ensure_ascii=False),
                "%s %s" % (st, str(wrong.get("detail"))[:40])))
st, ok = api("/api/login", {"username": user, "password": pw})
results.append(("本人持正确口令能看到被封", st == 403 and ok.get("code") == "account_banned", str(st)))
st, t = api("/api/chat/ticket", {}, token=token)
results.append(("封号的人领不到私信票据", st == 403, str(st)))

sql("UPDATE users SET banned_at=NULL, ban_reason='' WHERE id=?", (uid,), True)
st, d = api("/api/dashboard", token=token)
results.append(("解封之后主应用恢复", st == 200, str(st)))
results.append(("审计表还没建也不影响主应用（后台是旁路）",
                "admin_audit" not in [r["name"] for r in
                    sql("SELECT name FROM sqlite_master WHERE type='table'")], "本轮没往生产库塞后台表"))

# ---- 清理：按 id 显式删，逐表走外键自省 ----
# PRAGMA foreign_key_list 的列是 (id,seq,table,from,to,...)：table 是被引用的表，from 是本表的列
refs = []
for t in [r["name"] for r in sql("SELECT name FROM sqlite_master WHERE type='table' "
                                 "AND name NOT LIKE 'sqlite_%'")]:
    cols = {c["name"] for c in sql("PRAGMA table_info(%s)" % t)}
    conn = sqlite3.connect(DB)
    fk_cols = {row[3] for row in conn.execute("PRAGMA foreign_key_list(%s)" % t) if row[2] == "users"}
    conn.close()
    wanted = fk_cols | {c for c in cols if c in (
        "user_id", "follower_id", "followee_id", "from_id", "to_id", "blocker", "blocked",
        "reporter", "actor_id", "a_id", "b_id", "last_from")}
    refs += [(t, c) for c in sorted(wanted)]

conn = sqlite3.connect(DB, timeout=5)
conn.execute("PRAGMA busy_timeout=5000")
conn.execute("PRAGMA foreign_keys=ON")
conn.execute("PRAGMA defer_foreign_keys=ON")
conn.execute("BEGIN IMMEDIATE")
try:
    for table, col in refs:
        try:
            conn.execute("DELETE FROM %s WHERE %s=?" % (table, col), (uid,))
        except sqlite3.OperationalError:
            pass
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    bad = conn.execute("PRAGMA foreign_key_check").fetchall()
    if bad:
        conn.rollback()
        raise SystemExit("外键不自洽，已回滚，夹具账号还在：%d 条" % len(bad))
    conn.commit()
finally:
    conn.close()

left = sql("SELECT COUNT(*) AS c FROM users")[0]["c"]
results.append(("夹具账号已按 id 删除", sql("SELECT id FROM users WHERE id=?", (uid,)) == [], "剩 %d 个用户" % left))
results.append(("真实账号数量没被牵连", left == before_counts["users"],
                "删前 %d 删后 %d" % (before_counts["users"], left)))
drift = []
for t, n in before_counts.items():
    now_n = sql("SELECT COUNT(*) AS c FROM %s" % t)[0]["c"]
    if now_n != n:
        drift.append("%s %d->%d" % (t, n, now_n))
results.append(("除夹具外没有任何表被改动", drift == [], "; ".join(drift[:6])))

fails = [r for r in results if not r[1]]
for name, ok, detail in results:
    print("%s %s%s" % ("绿" if ok else "红", name, ("" if ok else "  -> " + detail)))
print("=== 线上封号自证：%d 条，绿 %d，红 %d ===" % (len(results), len(results) - len(fails), len(fails)))
print("EXIT=%d" % (0 if not fails else 1))
raise SystemExit(0 if not fails else 1)
