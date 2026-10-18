"""后台 ↔ App 联动自证（DoD 第 3 条：不是后台自己看自己）。

全部用一次性夹具：真实账号的数据一条都不改。
每一步都从"另一条路径"读回——后台写、App 读；App 写、后台读。
"""
import json
import secrets
import sqlite3
import sys
import urllib.error
import urllib.request

APP = "http://172.17.0.1:8000"
CONSOLE = "https://127.0.0.1"          # 经 nginx，含 Basic 与 /admin、/ops 前缀
DB = "/opt/qingsu/data/qingsu.db"
ADMIN = "/opt/qingsu/admin/console.json"
BUILD = "34"
SEC = json.load(open(ADMIN, encoding="utf-8"))
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), str(detail)[:220]))


def req(url, body=None, token=None, basic=None, xtoken=None, cookie=None, method=None, insecure=True):
    data = None if body is None else json.dumps(body).encode()
    h = {"Content-Type": "application/json", "X-App-Build": BUILD}
    if token:
        h["Authorization"] = "Bearer " + token        # Directus 那一侧
    if xtoken:
        h["X-Qingsu-Token"] = xtoken                   # 运维台那一侧（Authorization 已被 Basic 占）
    if basic:
        import base64
        h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % basic).encode()).decode()
    if cookie:
        h["Cookie"] = cookie
    r = urllib.request.Request(url, data=data, headers=h, method=method or ("POST" if data else "GET"))
    # opener.open() 不接 context：TLS 参数只能挂在 HTTPSHandler 上建 opener
    handlers = [urllib.request.ProxyHandler({})]
    if insecure and url.startswith("https"):
        import ssl
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    jump = urllib.request.build_opener(*handlers)
    try:
        with jump.open(r, timeout=25) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}"), dict(e.headers)
        except Exception:
            return e.code, {}, {}


def register(prefix):
    name = prefix + secrets.token_hex(4)
    pw = secrets.token_urlsafe(14)
    st, d, _ = req(APP + "/api/register", {"username": name, "password": pw, "age": 30,
                                           "height": 170, "weight_jin": 160, "target_weight_jin": 140})
    assert st == 200, (st, d)
    return {"name": name, "pw": pw, "id": d["id"], "token": d["token"]}


def cleanup(uid):
    c = sqlite3.connect(DB, timeout=5)
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA defer_foreign_keys=ON")
    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                      "AND name NOT LIKE 'sqlite_%'")]
    for t in tables:
        cols = {r[1] for r in c.execute("PRAGMA table_info(%s)" % t)}
        fks = {r[3] for r in c.execute("PRAGMA foreign_key_list(%s)" % t) if r[2] == "users"}
        for col in sorted(fks | {x for x in cols if x in (
                "user_id", "follower_id", "followee_id", "from_id", "to_id", "blocker", "blocked",
                "reporter", "actor_id", "a_id", "b_id", "last_from")}):
            try:
                c.execute("DELETE FROM %s WHERE %s=?" % (t, col), (uid,))
            except sqlite3.OperationalError:
                pass
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    if c.execute("PRAGMA foreign_key_check").fetchall():
        c.rollback()
        raise SystemExit("清理后外键不自洽，已回滚")
    c.commit()
    c.close()


basic = (SEC["basic_user"], SEC["basic_password"])
users = []
try:
    author = register("linkauthor_")
    reader = register("linkreader_")
    asker = register("linkasker_")
    users = [author["id"], reader["id"], asker["id"]]

    # ---- A. App 发帖 → 后台看得见 ----
    st, post, _ = req(APP + "/api/community/posts", {"text": "联动自证帖：只活在这一轮", "images": []},
                      token=author["token"])
    assert st == 200, (st, post)
    pid = post["post"]["id"]

    # 后台（Directus）用运营账号读这条帖子。
    # Directus 的 API 在源站根路径（/auth、/items…），Data Studio 才在 /admin；
    # 它的认证占用 Authorization: Bearer，所以这一侧不叠 Basic（同一格头，会互相顶掉）。
    st, ds, _ = req(CONSOLE + "/auth/login", {"email": SEC["operator_email"],
                                                    "password": SEC["operator_password"]})
    check("运营账号经 nginx 能登录数据控制台", st == 200 and ds.get("data", {}).get("access_token"),
          "%s %s" % (st, str(ds)[:120]))
    at = ds.get("data", {}).get("access_token", "")
    st, seen0, _ = req(CONSOLE + "/items/posts?limit=8&fields=id,user_id,status,body")
    check("没有 Directus 令牌时读不到业务数据", st in (401, 403), "%s %s" % (st, str(seen0)[:120]))
    st, seen, _ = req(CONSOLE + "/items/posts?limit=20&fields=id,user_id,status,body", token=at)
    ids = [r["id"] for r in (seen.get("data") or [])]
    check("App 发的帖子在后台列表里看得见", pid in ids, "pid=%s ids=%s %s" % (pid, ids, str(seen)[:120]))

    # ---- B. 后台下架 → App 信息流里消失，且行还在（不物理删）----
    st, upd, _ = req(CONSOLE + "/items/posts/%d" % pid,
                     {"status": "removed"}, token=at, method="PATCH")
    check("后台能下架帖子", st == 200, "%s %s" % (st, str(upd)[:160]))
    st, feed, _ = req(APP + "/api/community/feed", token=reader["token"])
    check("下架后 App 信息流里没有它",
          st == 200 and pid not in [p["id"] for p in feed.get("items", [])], str(feed)[:160])
    st, own, _ = req(APP + "/api/community/posts/%d" % pid, token=author["token"])
    check("下架后作者主页也看不到这条", st in (200, 404) and
          (st == 404 or own.get("post", {}).get("status") != "open"), "%s %s" % (st, str(own)[:120]))
    left = sqlite3.connect(DB).execute("SELECT status FROM posts WHERE id=?", (pid,)).fetchone()
    check("下架是改状态而不是删行（可恢复）", left and left[0] == "removed", str(left))

    # ---- C. App 提反馈 → 后台回复 → App 端看得见 ----
    st, fb, _ = req(APP + "/api/feedback", {"kind": "bug", "text": "联动自证：这条需要被回复",
                                            "page": "/settings"}, token=asker["token"])
    check("App 端能提交反馈", st == 200, "%s %s" % (st, str(fb)[:120]))
    fid = None
    st, mine, _ = req(APP + "/api/feedback/mine", token=asker["token"])
    if st == 200:
        items = mine.get("items") or mine.get("feedback") or []
        fid = items[0]["id"] if items else None
    check("反馈有 id 可回（App 自己的读路径）", fid is not None, str(mine)[:160])
    if fid:
        st, upd, _ = req(CONSOLE + "/items/feedback/%d" % fid,
                         {"status": "doing", "reply": "已排期，下一版修"},
                         token=at, method="PATCH")
        check("后台能改状态并写回复", st == 200, "%s %s" % (st, str(upd)[:200]))
        st, mine2, _ = req(APP + "/api/feedback/mine", token=asker["token"])
        got = (mine2.get("items") or mine2.get("feedback") or [{}])[0]
        check("App 端读到了后台写的回复原文",
              "已排期" in str(got.get("reply")) and got.get("status") == "doing",
              str(got)[:200])

    # ---- D. 运维台（/ops/）经 nginx：封号 → App 403 ----
    st, lg, _ = req(CONSOLE + "/ops/api/login", {"token": SEC["ops_token"]}, basic=basic, method="POST")
    check("运维台经 nginx 能登录（https 下才谈得上 Secure cookie）",
          st == 200, "%s %s" % (st, str(lg)[:120]))
    st, ov, _ = req(CONSOLE + "/ops/api/overview", basic=basic)   # 只有 Basic：应被 L3 拒
    check("经 nginx 时只过 Basic 仍读不到运维数据", st in (401, 403), "%s %s" % (st, str(ov)[:120]))
    st, ov, _ = req(CONSOLE + "/ops/api/overview", basic=basic, xtoken=SEC["ops_token"])
    check("Basic + 令牌头能读到运维概览（两层各管一段）", st == 200 and "counts" in str(ov),
          "%s %s" % (st, str(ov)[:140]))

    st, r, _ = req(CONSOLE + "/ops/api/users/%d/ban" % reader["id"],
                   {"expect_username": reader["name"], "reason": "联动自证封号"},
                   basic=basic, xtoken=SEC["ops_token"], method="POST")
    check("经 nginx 封号成功", st == 200, "%s %s" % (st, str(r)[:160]))
    st, d, _ = req(APP + "/api/dashboard", token=reader["token"])
    check("封号之后 App 侧 403 且带原因",
          st == 403 and "联动自证" in str(d.get("detail")), "%s %s" % (st, str(d)[:140]))
    st, r, _ = req(CONSOLE + "/ops/api/users/%d/unban" % reader["id"],
                   {"expect_username": reader["name"]}, basic=basic,
                   xtoken=SEC["ops_token"], method="POST")
    check("经 nginx 解封成功", st == 200, "%s %s" % (st, str(r)[:140]))
    st, d, _ = req(APP + "/api/dashboard", token=reader["token"])
    check("解封之后 App 恢复正常", st == 200, "%s %s" % (st, str(d)[:120]))
finally:
    for uid in users:
        try:
            cleanup(uid)
        except SystemExit:
            raise
        except Exception as e:
            print("清理失败 id=%s：%s" % (uid, e))
    left = sqlite3.connect(DB).execute(
        "SELECT COUNT(*) FROM users WHERE username LIKE 'link%_' OR username LIKE 'houkou%'").fetchone()[0]
    check("夹具账号全部清干净", left == 0, "剩 %d 个" % left)
    real = sqlite3.connect(DB).execute("SELECT COUNT(*) FROM users").fetchone()[0]
    check("真实账号数量不变（应为 2）", real == 2, "现在 %d 个" % real)
    bad = sqlite3.connect(DB).execute("PRAGMA foreign_key_check").fetchall()
    check("外键自洽", not bad, "%d 条" % len(bad))
    ok = sqlite3.connect(DB).execute("PRAGMA integrity_check").fetchone()[0]
    check("库完整性 ok", ok == "ok", ok)

fails = 0
for name, ok, detail in RESULTS:
    print("%s %s%s" % ("绿" if ok else "红", name, "" if ok else "  -> " + detail))
    fails += 0 if ok else 1
print("=== 后台↔App 联动：%d 条，绿 %d，红 %d ===" % (len(RESULTS), len(RESULTS) - fails, fails))
sys.exit(0 if fails == 0 else 1)
