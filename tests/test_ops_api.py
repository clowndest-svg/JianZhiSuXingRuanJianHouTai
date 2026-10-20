"""运维 API 的契约与安全测试（L 档：全程打一份复制库，绝不碰生产文件）。

分档见 docs/05 §1。这个文件里最重要的一组是"跨进程自证"：
后台按下封号 → 主应用自己必须 403。只验"后台写了库"，等于验了半件事。

注意两个 Windows 坑：server.py 在 import 时就读环境变量并建目录，
所以必须"先设 env 再 import"，而且每个用例都重新 import 一份。
"""
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent
APP_REPO = Path(os.environ.get("QINGSU_APP_REPO", r"D:\RuanJian\JiaZhiSuXianApk"))
sys.path.insert(0, str(BACKEND / "ops"))
sys.path.append(str(APP_REPO))        # 主应用 import 自己的 app_modules 包，路径要能找到
# server.py 里是 `from app_modules...`，所以主仓根目录也要在路径上
sys.path.insert(0, str(APP_REPO))

from fastapi.testclient import TestClient  # noqa: E402

if not (APP_REPO / "server.py").is_file():
    raise SystemExit("找不到主应用仓库 %s：跨进程自证跑不了，判据不能空转" % APP_REPO)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class OpsApi(unittest.TestCase):
    def setUp(self):
        (BACKEND / ".tmp").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=str(BACKEND / ".tmp"))
        root = Path(self.tmp.name)
        for name in ("DATA", "UPLOAD", "WEB", "KEYS", "BACKUPS"):
            (root / name).mkdir()
        os.environ.update({
            "QINGSU_DB_DIR": str(root / "DATA"),
            "QINGSU_UPLOAD_DIR": str(root / "UPLOAD"),
            "QINGSU_WEB_DIR": str(root / "WEB"),
            "QINGSU_KEY_DIR": str(root / "KEYS"),
            "QINGSU_MIN_BUILD_FILE": str(root / "DATA" / "min_build"),
        })
        self.db = root / "DATA" / "qingsu.db"
        (root / "DATA" / "min_build").write_text("0", encoding="utf-8")
        (root / "WEB" / "version.json").write_text(
            json.dumps({"version_code": 34, "min_version_code": 34}), encoding="utf-8")

        # env 就位之后才 import 主应用：它在 import 期就建目录、跑 migrate_db
        self.app_mod = load(APP_REPO / "server.py", "qingsu_app_for_ops")
        # 本机若有真 Redis，限流计数会跨测试残留（实测：反馈口十分钟内会 429）。
        # 和主应用集成测试一样打桩成"Redis 不可用"，让判据只看逻辑不看当天运气。
        self.app_mod._redis_cmd = lambda *a, **k: (False, None)
        self.app = TestClient(self.app_mod.app)
        self.app_body = dict(username="opsowner", password="Review!123", age=30, height=170,
                             weight_jin=160, target_weight_jin=140)
        self.signup = self.app.post("/api/register", json=self.app_body).json()
        other = self.app.post("/api/register", json=dict(self.app_body, username="opsother")).json()
        self.other = {"token": other["token"], "id": other["id"],
                      # sessions 的主键是 token_hash（没有 id 列），计数只能挑一个真实存在的列
                      "sessions": len(self.sql("SELECT token_hash FROM sessions WHERE user_id=?",
                                               (other["id"],)))}
        root = Path(self.tmp.name)

        os.environ.update({
            "QINGSU_DB": str(self.db),
            "QINGSU_BACKUP_DIR": str(root / "BACKUPS"),
            "QINGSU_BACKUP_SCRIPT": str(root / "backup.py"),
            "QINGSU_LOCAL_API": "http://127.0.0.1:1",       # 故意指向没人听的端口：看它会不会谎报
            "QINGSU_CONSOLE_CONTAINER": "no-such-container",
            "QINGSU_PYTHON_BIN": sys.executable,            # Windows 上 python3 是商店别名，不能用
            "OPS_TOKEN": "dev-token-please-rotate",
            "OPS_COOKIE_SECRET": "dev-cookie-secret",
            "ALLOW_ENV_TOKEN": "1",
            "OPS_INSECURE_COOKIE": "1",
            "OPS_BASIC_USER": "qingsu",
            "OPS_BASIC_PASSWORD": "dev-basic-pw",
            "QINGSU_MAIL_CONFIG": str(root / 'mail.json'),
            "QINGSU_MAIL_CHECK": str(root / 'mail-check.json'),
            "QINGSU_MONITOR_FILE": str(root / 'monitor.json'),
        })
        self.ops_mod = load(BACKEND / "ops" / "admin_api.py", "qingsu_ops_api")
        self.ops = TestClient(self.ops_mod.app, headers={
            "Authorization": "Basic " + __import__("base64").b64encode(b"qingsu:dev-basic-pw").decode()})
        # L2 的 Basic 与 L3 的令牌是分开的两层：这台 TestClient 默认带 Basic，
        # 不带令牌/cookie 的用例测的就是"过了外层闸、没登录运维台"这一种形状。
        self.bare = TestClient(self.ops_mod.app)
        self.bearer = {"X-Qingsu-Token": "dev-token-please-rotate"}
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    # ---- 小工具 ----
    def sql(self, query, args=()):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in conn.execute(query, args).fetchall()]
            conn.commit()
            return rows
        finally:
            conn.close()

    def sessions_of(self, uid):
        # sessions 表的主键是 token_hash，没有 id 列（线上真实结构）
        return len(self.sql("SELECT token_hash FROM sessions WHERE user_id=?", (uid,)))

    def auth(self):
        return {"Authorization": "Bearer " + self.signup["token"]}

    def authed(self):
        r = self.ops.post("/api/login", json={"token": "dev-token-please-rotate"})
        self.assertEqual(r.status_code, 200, r.text)

    def audits(self, action=None):
        rows = self.ops.get("/api/audit?limit=100", headers=self.bearer).json()["items"]
        return [a for a in rows if action is None or a["action"] == action]

    def test_mail_config_does_not_return_or_audit_password(self):
        body = dict(host='smtp.example.com', port=465, tls='ssl', user='tester@example.com', password='PRIVATE_SMTP_SECRET', enabled=True)
        body['from'] = 'tester@example.com'
        r = self.ops.post('/api/mail', json=body, headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn('PRIVATE_SMTP_SECRET', r.text)
        self.assertNotIn('PRIVATE_SMTP_SECRET', self.ops.get('/api/mail', headers=self.bearer).text)
        self.assertNotIn('PRIVATE_SMTP_SECRET', json.dumps(self.audits()))
        saved = json.loads((self.root / 'mail.json').read_text())
        self.assertEqual(saved['password'], 'PRIVATE_SMTP_SECRET')
        r = self.ops.post('/api/mail', json=dict(body, password=''), headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(json.loads((self.root / 'mail.json').read_text())['password'], 'PRIVATE_SMTP_SECRET')
        self.assertEqual(self.ops.post('/api/mail', json=dict(body, host='other.example.com', password=''), headers=self.bearer).status_code, 400)

    def test_mail_check_is_truthful_and_sanitizes_provider_errors(self):
        self.assertEqual(self.ops.post('/api/mail/check', headers=self.bearer).status_code, 400)
        self.ops.post('/api/mail', headers=self.bearer, json={'host': 'smtp.example.com', 'port': 465, 'tls': 'ssl', 'user': 'test', 'from': 'test@example.com', 'password': 'PRIVATE_SECRET'})
        def reject(raw):
            raise RuntimeError('PRIVATE_SECRET provider diagnostics')
        self.ops_mod._check_smtp = reject
        r = self.ops.post('/api/mail/check', headers=self.bearer)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()['ok'])
        self.assertFalse(r.json()['delivery_tested'])
        self.assertNotIn('PRIVATE_SECRET', r.text)
        self.ops_mod._mail_check_at = 0
        self.ops_mod._check_smtp = lambda raw: None
        r = self.ops.post('/api/mail/check', headers=self.bearer)
        self.assertTrue(r.json()['ok'])
        self.assertFalse(r.json()['delivery_tested'])

    def test_mail_configuration_requires_both_authentication_layers(self):
        self.assertEqual(self.bare.get('/api/mail').status_code, 401)
        self.assertEqual(self.ops.get('/api/mail').status_code, 401)
        self.assertFalse(self.ops.get('/api/mail', headers=self.bearer).json()['config']['enabled'])
        self.assertEqual(self.ops.post('/api/mail', headers=self.bearer, json={'enabled': False}).status_code, 200)
        self.assertFalse(json.loads((self.root / 'mail.json').read_text())['enabled'])

    def test_admin_writes_reject_cross_site_origin(self):
        r = self.ops.post('/api/mail', headers={**self.bearer, 'Origin': 'https://evil.test'}, json={'enabled': False})
        self.assertEqual(r.status_code, 403)

    def test_sensitive_push_and_invite_fields_are_redacted_in_audit(self):
        self.ops_mod.audit('test', 'test', 'push_subscriptions', 'fixture', before={'endpoint': 'PRIVATE_ENDPOINT', 'keys_json': 'PRIVATE_KEYS', 'session_hash': 'PRIVATE_SESSION', 'failures': 0})
        text = json.dumps(self.audits('test'))
        for marker in ('PRIVATE_ENDPOINT', 'PRIVATE_KEYS', 'PRIVATE_SESSION'):
            self.assertNotIn(marker, text)

    # ---- 鉴权 ----
    def test_feedback_and_reports_lists_are_ready_to_work_from(self):
        """运维页要能一眼看到"有什么要处理"，而不是只有计数。"""
        # 直接落库：这条用例测的是运维 API 的列表，不测 App 的投递与限流
        self.sql("INSERT INTO feedback(user_id,kind,body,page,app_build,contact,status,reply,created_at)"
                 " VALUES (?,?,?,?,?,?,?,?,?)",
                 (self.signup["id"], "bug", "运维页要看得到这条", "/me", 34, "", "new", "",
                  "2026-10-19 00:00:00"))
        fb = self.ops.get("/api/feedback?limit=5", headers=self.bearer).json()
        self.assertTrue(fb.get("items"), "反馈列表是空的")
        self.assertIn("new", fb.get("counts", {}), "状态计数里没有 new")
        self.assertTrue(any("运维页要看得到" in (x.get("body") or "") for x in fb["items"]))
        self.assertNotIn("password_hash", json.dumps(fb, ensure_ascii=False))
        self.sql("INSERT INTO content_reports(target_kind,target_id,reporter,reason,created_at) "
                 "VALUES ('post',1,?, '测试举报理由', '2026-10-18 23:00:00')", (self.signup["id"],))
        rp = self.ops.get("/api/reports?limit=5", headers=self.bearer).json()
        self.assertTrue(rp.get("items"), "举报列表是空的：%s" % json.dumps(rp, ensure_ascii=False)[:300])
        self.assertIn("测试举报理由", json.dumps(rp, ensure_ascii=False))
        self.assertNotIn("password_hash", json.dumps(rp, ensure_ascii=False))

    def test_feedback_reply_and_report_moderation_round_trip(self):
        """工单回复回到 App；举报处理软下架内容并在同一事务留下审计。"""
        feedback = self.app.post("/api/feedback", headers=self.auth(),
                                 json={"kind": "bug", "text": "私信页面顶部空白",
                                       "page": "/community", "contact": ""})
        self.assertEqual(feedback.status_code, 200, feedback.text)
        fid = feedback.json()["id"]
        detail = self.ops.get("/api/feedback/%d" % fid, headers=self.bearer).json()
        self.assertEqual(detail["status"], "new")
        saved = self.ops.patch("/api/feedback/%d" % fid, headers=self.bearer,
                               json={"expected_status": "new", "status": "doing",
                                     "reply": "已经修复，请更新应用后查看。"})
        self.assertEqual(saved.status_code, 200, saved.text)
        visible = self.app.get("/api/feedback/mine", headers=self.auth()).json()["items"]
        own_feedback = next(x for x in visible if x["id"] == fid)
        self.assertEqual(own_feedback["status"], "doing")
        self.assertEqual(own_feedback["reply"], "已经修复，请更新应用后查看。")
        stale = self.ops.patch("/api/feedback/%d" % fid, headers=self.bearer,
                               json={"expected_status": "new", "status": "done", "reply": "过期写入"})
        self.assertEqual(stale.status_code, 409, "旧页面不应覆盖刚保存的工单")

        post = self.app.post("/api/community/posts", headers=self.auth(),
                             json={"text": "被举报测试帖子", "images": [],
                                   "request_id": "ops-report-post"}).json()["post"]
        other_headers = {"Authorization": "Bearer " + self.other["token"]}
        submitted = self.app.post("/api/community/report", headers=other_headers,
                                  json={"kind": "post", "target_id": post["id"], "reason": "测试广告"})
        self.assertEqual(submitted.status_code, 200, submitted.text)
        queue = self.ops.get("/api/reports?status=open", headers=self.bearer).json()["items"]
        report = next(x for x in queue if x["target_id"] == post["id"])
        self.assertEqual(report["target"]["body"], "被举报测试帖子")
        self.assertEqual(report["target"]["author"], "opsowner")
        removed = self.ops.post("/api/reports/%d/resolve" % report["id"], headers=self.bearer,
                                json={"action": "remove", "expected_status": "open", "note": "确认属于广告内容"})
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertEqual(self.sql("SELECT status FROM posts WHERE id=?", (post["id"],))[0]["status"], "deleted")
        self.assertEqual(self.sql("SELECT status FROM content_reports WHERE id=?", (report["id"],))[0]["status"],
                         "actioned")
        self.assertEqual(self.ops.post("/api/reports/%d/resolve" % report["id"], headers=self.bearer,
                                      json={"action": "remove", "expected_status": "open",
                                            "note": "重复处理"}).status_code, 409)
        self.assertTrue(self.audits("remove_reported_post"), "下架和审计没有一起提交")

        second_post = self.app.post("/api/community/posts", headers=self.auth(),
                                    json={"text": "评论举报测试", "images": [],
                                          "request_id": "ops-report-comment"}).json()["post"]
        comment = self.app.post("/api/community/posts/%d/comments" % second_post["id"],
                                headers=other_headers,
                                json={"text": "被举报评论", "request_id": "ops-report-comment-1"}).json()["comment"]
        submitted = self.app.post("/api/community/report", headers=self.auth(),
                                  json={"kind": "comment", "target_id": comment["id"], "reason": "测试辱骂"})
        self.assertEqual(submitted.status_code, 200, submitted.text)
        report = next(x for x in self.ops.get("/api/reports?status=open", headers=self.bearer).json()["items"]
                      if x["target_id"] == comment["id"])
        result = self.ops.post("/api/reports/%d/resolve" % report["id"], headers=self.bearer,
                               json={"action": "remove", "expected_status": "open", "note": "确认违反评论规范"})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(self.sql("SELECT status FROM comments WHERE id=?", (comment["id"],))[0]["status"],
                         "deleted")
        self.assertEqual(self.sql("SELECT comment_count FROM posts WHERE id=?",
                                  (second_post["id"],))[0]["comment_count"], 0)

        # 驳回只更新队列状态，不碰帖子；记录仍可查询。
        third_post = self.app.post("/api/community/posts", headers=self.auth(),
                                   json={"text": "驳回举报测试", "images": [],
                                         "request_id": "ops-report-dismiss"}).json()["post"]
        self.app.post("/api/community/report", headers=other_headers,
                      json={"kind": "post", "target_id": third_post["id"], "reason": "误报"})
        report = next(x for x in self.ops.get("/api/reports?status=open", headers=self.bearer).json()["items"]
                      if x["target_id"] == third_post["id"])
        dismissed = self.ops.post("/api/reports/%d/resolve" % report["id"], headers=self.bearer,
                                  json={"action": "dismiss", "expected_status": "open", "note": "复核后属于正常分享"})
        self.assertEqual(dismissed.status_code, 200, dismissed.text)
        self.assertEqual(self.sql("SELECT status FROM posts WHERE id=?", (third_post["id"],))[0]["status"], "open")
        self.assertEqual(self.sql("SELECT status FROM content_reports WHERE id=?", (report["id"],))[0]["status"],
                         "dismissed")

    def test_downstream_errors_are_not_masked_as_401(self):
        """中间件曾把下游的任何异常都吞掉并返回 401——排查时看起来像"口令错"，实际是接口炸了。
        这是本轮真实踩到的 bug，钉住：异常必须冒成 500。"""
        @self.ops_mod.app.get("/api/__boom")
        def boom():
            raise RuntimeError("boom")
        c = TestClient(self.ops_mod.app, headers=self.ops.headers, raise_server_exceptions=False)
        r = c.get("/api/__boom")
        self.assertNotEqual(r.status_code, 401, "下游异常又被当成未授权了")
        self.assertEqual(r.status_code, 500, "异常没有被冒出来：%s" % r.status_code)

    def test_user_listing_finds_people_without_leaking_columns(self):
        self.assertEqual(self.ops.get("/api/users").status_code, 401)
        for term in ("opsowner", str(self.signup["id"]), "opsother"):
            r = self.ops.get("/api/users?q=%s" % term, headers=self.bearer).json()
            self.assertGreaterEqual(r["count"], 1, "搜 %s 应该能找到人" % term)
        text = self.ops.get("/api/users?limit=50", headers=self.bearer).text
        for word in ("password_hash", "pw_salt", "share_secret", "token_hash"):
            self.assertNotIn(word, text, "用户列表带出了凭据列 " + word)
        self.assertIn("banned_at", text, "列表里没有封号状态，运营就看不出谁是被停用的")
        self.assertIn("sessions", text, "没有会话数就没法解释'撤销会话'会踢掉几个人")
        capped = self.ops.get("/api/users?limit=99999", headers=self.bearer).json()
        self.assertLessEqual(len(capped["items"]), 50, "limit 不封顶，等于给后台开了拖全库的口子")

    def test_user_detail_counts_match_the_detail_tables(self):
        self.app.post("/api/weight/log", headers=self.auth(), json={"weight_jin": 148})
        d = self.ops.get("/api/users/%d" % self.signup["id"], headers=self.bearer).json()
        real = self.sql("SELECT COUNT(*) c FROM weight_logs WHERE user_id=?", (self.signup["id"],))[0]["c"]
        self.assertEqual(d["counts"].get("weight_logs"), real, "详情里的体重条数与明细表不一致")
        for word in ("password_hash", "pw_salt", "loc_lat", "loc_lng"):
            self.assertNotIn(word, json.dumps(d, ensure_ascii=False), "详情带出敏感列 " + word)
        self.assertEqual(self.ops.get("/api/users/999999", headers=self.bearer).status_code, 404)

    def test_basic_layer_is_a_separate_gate_from_the_token(self):
        import base64
        good = "Basic " + base64.b64encode(b"qingsu:dev-basic-pw").decode()
        wrong = "Basic " + base64.b64encode(b"qingsu:wrong-guess").decode()
        # 有运维令牌但没过 Basic：外层闸先拦（两层各自独立，缺一层就进不来）
        self.assertEqual(self.bare.get("/api/overview",
                         headers={"X-Qingsu-Token": "dev-token-please-rotate"}).status_code, 401,
                         "Basic 这层没生效，令牌等于唯一的门")
        r = self.bare.get("/api/whoami", headers={"Authorization": wrong})
        self.assertEqual(r.status_code, 401, "错的 Basic 口令放进来了")
        self.assertIn("basic", str(r.headers.get("www-authenticate", "")).lower(),
                      "401 没带挑战头，浏览器不会弹口令框")
        self.assertEqual(self.ops.get("/api/whoami", headers=self.bearer).json()["actor"], "script")

    def test_missing_basic_password_refuses_service_instead_of_opening_it(self):
        # "忘了配 Basic" 最坏的形状是它一直开着而没人知道，所以缺口令必须拒绝服务
        orig = self.ops_mod.basic_gate
        self.ops_mod.basic_gate = lambda: ("qingsu", "")
        try:
            r = self.bare.get("/api/overview", headers={"Authorization": "Basic whatever"})
            self.assertEqual(r.status_code, 503, "口令没配好时不该敞开，也不该装作正常")
        finally:
            self.ops_mod.basic_gate = orig

    def test_every_data_endpoint_requires_auth(self):
        for path in ("/api/health", "/api/overview", "/api/gate", "/api/audit",
                     "/api/users", "/api/users/%d" % self.signup["id"],
                     "/api/users/%d/export" % self.signup["id"],
                     "/api/feedback", "/api/feedback/1", "/api/reports"):
            self.assertEqual(self.ops.get(path).status_code, 401, path + " 不该免登录")
        self.assertEqual(self.ops.patch("/api/feedback/1", json={"status": "done",
                         "expected_status": "new", "reply": "x"}).status_code, 401)
        self.assertEqual(self.ops.post("/api/reports/1/resolve",
                         json={"action": "dismiss", "expected_status": "open", "note": "x"}).status_code, 401)
        for path, body in (("/api/users/%d/ban" % self.signup["id"], {"reason": "x"}),
                           ("/api/gate", {"expect_current": 0, "new": 1}),
                           ("/api/backup", {})):
            self.assertEqual(self.ops.post(path, json=body).status_code, 401, path + " 不该免登录")
        self.authed()
        self.assertEqual(self.ops.get("/api/overview").status_code, 200, "cookie 会话没生效")

    def test_wrong_token_is_audited_and_eventually_locked(self):
        for _ in range(8):
            self.assertEqual(self.ops.post("/api/login", json={"token": "nope"}).status_code, 401)
        locked = self.ops.post("/api/login", json={"token": "dev-token-please-rotate"})
        self.assertEqual(locked.status_code, 429, "输错八次之后还能继续试，等于没有闸门")
        fails = self.audits("login_failed")
        self.assertGreaterEqual(len(fails), 8, "失败的尝试没留痕，事后查不到谁在撞")
        self.assertNotIn("nope", json.dumps(fails, ensure_ascii=False), "审计里把试过的口令记下来了")

    def test_bearer_and_cookie_both_work_but_logout_clears_cookie(self):
        self.authed()
        self.assertEqual(self.ops.get("/api/whoami").json()["actor"], "console")
        self.ops.post("/api/logout", headers=self.bearer)
        self.assertEqual(self.ops.get("/api/whoami").status_code, 401)
        self.assertEqual(self.ops.get("/api/whoami", headers=self.bearer).json()["actor"], "script")

    def test_tampered_cookie_is_refused(self):
        self.authed()
        forged = self.ops_mod.make_session("console").rsplit(".", 1)[0] + "." + "0" * 32
        self.ops.cookies.clear()
        self.ops.cookies.set("qops", forged)
        self.assertEqual(self.ops.get("/api/whoami").status_code, 401, "签名没校验住伪造的会话")

    # ---- 封号：跨进程自证 ----
    def test_ban_needs_reason_and_exact_username(self):
        r = self.ops.post("/api/users/%d/ban" % self.signup["id"],
                          json={"expect_username": "opsowner"}, headers=self.bearer)
        self.assertEqual(r.status_code, 422, "没原因也能封号")
        r = self.ops.post("/api/users/%d/ban" % self.signup["id"],
                          json={"expect_username": "写错的人", "reason": "试"}, headers=self.bearer)
        self.assertEqual(r.status_code, 409, "用户名对不上却执行了")
        self.assertIsNone(self.sql("SELECT banned_at FROM users WHERE id=?",
                                   (self.signup["id"],))[0]["banned_at"], "被拒的动作居然还是改了库")

    def test_ban_then_the_app_itself_refuses(self):
        self.assertEqual(self.app.get("/api/dashboard", headers=self.auth()).status_code, 200)
        r = self.ops.post("/api/users/%d/ban" % self.signup["id"],
                          json={"expect_username": "opsowner", "reason": "刷屏"}, headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        blocked = self.app.get("/api/dashboard", headers=self.auth())
        self.assertEqual(blocked.status_code, 403, "后台封了号，主应用照旧放行——那这个标记就是装饰")
        self.assertEqual(blocked.json().get("code"), "account_banned")
        self.assertIn("刷屏", blocked.json()["detail"], "封号原因没带到用户端")
        self.assertEqual(self.app.get("/api/dashboard",
                         headers={"Authorization": "Bearer " + self.other["token"]}).status_code, 200)
        again = self.ops.post("/api/users/%d/ban" % self.signup["id"],
                              json={"expect_username": "opsowner", "reason": "刷屏"}, headers=self.bearer)
        self.assertEqual(again.status_code, 200)
        self.assertTrue(again.json().get("already"), "重复封号要说'已经封着'，不许报错也不许静默")
        row = self.audits("ban")[-1]
        # /api/audit 已经把 before/after 解析成对象返回了，这里不能再 json.loads
        self.assertIsNone(row["before_json"]["banned_at"], "改动前明明是封着的")
        self.assertIsNotNone(row["after_json"]["banned_at"], "改动后没记下新状态")
        self.assertEqual(row["after_json"]["ban_reason"], "刷屏")
        self.ops.post("/api/users/%d/unban" % self.signup["id"],
                      json={"expect_username": "opsowner"}, headers=self.bearer)
        self.assertEqual(self.app.get("/api/dashboard", headers=self.auth()).status_code, 200,
                         "解封之后主应用还在拦")

    def test_banned_user_cannot_get_a_chat_ticket(self):
        self.ops.post("/api/users/%d/ban" % self.signup["id"],
                      json={"expect_username": "opsowner", "reason": "测试"}, headers=self.bearer)
        r = self.app.post("/api/chat/ticket", headers=self.auth())
        self.assertEqual(r.status_code, 403, "被封的人还能领私信票据")

    # ---- 会话与口令 ----
    def test_revoke_sessions_kills_tokens_and_leaves_others_alone(self):
        extra = self.app.post("/api/login", json={"username": "opsowner",
                                                 "password": "Review!123"}).json()["token"]
        n = self.sessions_of(self.signup["id"])
        r = self.ops.post("/api/users/%d/revoke-sessions" % self.signup["id"],
                          json={"expect_username": "opsowner"}, headers=self.bearer)
        self.assertEqual(r.json()["revoked"], n, "撤销条数与实际会话数不符")
        self.assertEqual(self.app.get("/api/dashboard",
                     headers={"Authorization": "Bearer " + extra}).status_code, 401)
        self.assertEqual(self.sessions_of(self.other["id"]),
                         self.other["sessions"], "别人的会话被一起删了")

    def test_reset_password_revokes_old_sessions_and_the_new_pw_works(self):
        old_token = self.signup["token"]
        r = self.ops.post("/api/users/%d/reset-password" % self.signup["id"],
                          json={"expect_username": "opsowner"}, headers=self.bearer)
        otp = r.json()["one_time_password"]
        self.assertEqual(self.app.get("/api/dashboard",
                     headers={"Authorization": "Bearer " + old_token}).status_code, 401,
                     "换了口令但旧 token 还能用：'改密码踢掉登录'是句假话")
        logged = self.app.post("/api/login", json={"username": "opsowner", "password": otp})
        self.assertEqual(logged.status_code, 200, "一次性口令登不进去：%s" % logged.text)
        self.assertEqual(self.app.post("/api/login", json={"username": "opsowner",
                                 "password": "Review!123"}).status_code, 400, "旧口令居然还能登")
        # 我算的 scrypt 必须能被主应用自己的校验函数接受（不靠"看起来一样"）
        row = self.sql("SELECT password_hash, pw_salt FROM users WHERE id=?", (self.signup["id"],))[0]
        self.assertTrue(self.app_mod.verify_pw(otp, row),
                        "运维 API 算出的口令散列与主应用不兼容")
        self.assertNotIn(otp, json.dumps(self.audits("reset_pw"), ensure_ascii=False),
                         "一次性口令落进审计了")

    # ---- 注销 ----
    def test_delete_account_requires_exact_row_count(self):
        self.app.post("/api/weight/log", headers=self.auth(), json={"weight_jin": 150})
        # 先给另一个账号留一条记录，删号之后必须原封不动
        self.app.post("/api/weight/log",
                      headers={"Authorization": "Bearer " + self.other["token"]},
                      json={"weight_jin": 142})
        other_before = self.sql("SELECT COUNT(*) c FROM weight_logs WHERE user_id=?",
                                (self.other["id"],))[0]["c"]
        plan = self.ops.post("/api/users/%d/delete-account" % self.signup["id"],
                             json={"expect_username": "opsowner", "plan_only": True},
                             headers=self.bearer).json()
        self.assertGreater(plan["rows"], 0)
        for item in plan["plan"]:
            real = self.sql("SELECT COUNT(*) c FROM %s WHERE %s=?" % (item["table"], item["column"]),
                            (self.signup["id"],))[0]["c"]
            self.assertEqual(real, item["rows"], "%s.%s 的条数对不上" % (item["table"], item["column"]))
        wrong = self.ops.post("/api/users/%d/delete-account" % self.signup["id"],
                              json={"expect_username": "opsowner", "confirm_rows": plan["rows"] + 3},
                              headers=self.bearer)
        self.assertEqual(wrong.status_code, 409, "行数对不上却还是删了")
        self.assertEqual(len(self.sql("SELECT id FROM users WHERE id=?", (self.signup["id"],))), 1)
        good = self.ops.post("/api/users/%d/delete-account" % self.signup["id"],
                             json={"expect_username": "opsowner", "confirm_rows": plan["rows"]},
                             headers=self.bearer)
        self.assertEqual(good.status_code, 200, good.text)
        self.assertEqual(self.sql("SELECT id FROM users WHERE id=?", (self.signup["id"],)), [])
        self.assertEqual(self.sql("PRAGMA foreign_key_check"), [], "删完留了孤儿行")
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM users")[0]["c"], 1, "别人的账号被牵连了")
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM weight_logs WHERE user_id=?",
                                  (self.other["id"],))[0]["c"], other_before,
                         "别人的记录被一起删掉了")
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM weight_logs")[0]["c"], other_before,
                         "整张表被清空式的删除")

    def test_delete_account_survives_other_peoples_interactions_on_its_posts(self):
        """别人点赞/评论/收藏了要删的账号的帖子时，只按 user_id 删会撞外键整笔回滚。
        线上实测踩到：第一条删号 500、账号还在。这里钉住‘依赖行先清、别人的别处数据不动’。"""
        post = self.app.post("/api/community/posts", headers=self.auth(),
                             json={"text": "要删的账号发的帖子", "images": [],
                                   "request_id": "del-dep-1"}).json()["post"]
        pid = int(post["id"])
        other_h = {"Authorization": "Bearer " + self.other["token"]}
        self.assertEqual(self.app.post("/api/community/posts/%d/like" % pid,
                                       headers=other_h, json={"on": True}).status_code, 200)
        self.assertEqual(self.app.post("/api/community/posts/%d/favorite" % pid,
                                       headers=other_h, json={"on": True}).status_code, 200)
        self.assertEqual(self.app.post("/api/community/posts/%d/comments" % pid, headers=other_h,
                                       json={"text": "别人的评论", "request_id": "del-dep-c1"}).status_code, 200)
        # 另一个账号自己发一帖，删号后必须原封不动
        keep = self.app.post("/api/community/posts", headers=other_h,
                             json={"text": "不该被牵连的帖子", "images": [],
                                   "request_id": "del-dep-2"}).json()["post"]
        plan = self.ops.post("/api/users/%d/delete-account" % self.signup["id"],
                             json={"expect_username": "opsowner", "plan_only": True},
                             headers=self.bearer).json()
        dep = {x["table"]: x["rows"] for x in plan.get("dependents", [])}
        self.assertEqual(dep.get("post_likes"), 1, "依赖清单漏了别人的点赞：%s" % dep)
        self.assertEqual(dep.get("post_favorites"), 1, "依赖清单漏了别人的收藏：%s" % dep)
        self.assertEqual(dep.get("comments"), 1, "依赖清单漏了别人的评论：%s" % dep)
        # 页面上的"待删行数"必须把依赖行算进去，否则确认键永远对不上
        self.assertEqual(plan["rows"], sum(x["rows"] for x in plan["plan"]) + sum(dep.values()))
        good = self.ops.post("/api/users/%d/delete-account" % self.signup["id"],
                             json={"expect_username": "opsowner", "confirm_rows": plan["rows"]},
                             headers=self.bearer)
        self.assertEqual(good.status_code, 200, good.text)
        self.assertEqual(self.sql("SELECT id FROM users WHERE id=?", (self.signup["id"],)), [])
        self.assertEqual(self.sql("PRAGMA foreign_key_check"), [], "删完留了指向已删帖子的行")
        self.assertEqual(self.sql("SELECT id FROM posts WHERE id=?", (pid,)), [], "要删账号的帖子还在")
        self.assertEqual(len(self.sql("SELECT id FROM posts WHERE id=?", (int(keep["id"]),))), 1,
                         "别人自己的帖子被牵连删掉了")
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM post_likes WHERE post_id=?",
                                  (pid,))[0]["c"], 0, "别人对已删帖子的点赞没清")
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM post_favorites WHERE post_id=?",
                                  (pid,))[0]["c"], 0, "别人对已删帖子的收藏没清")
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM comments WHERE post_id=?",
                                  (pid,))[0]["c"], 0, "别人对已删帖子的评论没清")

    def test_delete_plan_and_audit_never_carry_credentials(self):
        self.ops.post("/api/users/%d/ban" % self.signup["id"],
                      json={"expect_username": "opsowner", "reason": "测试"}, headers=self.bearer)
        plan = self.ops.post("/api/users/%d/delete-account" % self.signup["id"],
                             json={"expect_username": "opsowner", "plan_only": True},
                             headers=self.bearer).json()
        body = json.dumps(plan, ensure_ascii=False) + json.dumps(self.audits(), ensure_ascii=False)
        for word in ("password_hash", "pw_salt", "share_secret", "token_hash"):
            self.assertNotIn(word, body, "计划/审计里出现了凭据列名 " + word)

    # ---- 导出与看板 ----
    def test_export_is_only_this_user_and_free_of_credentials(self):
        self.app.post("/api/weight/log", headers=self.auth(), json={"weight_jin": 149})
        text = self.ops.get("/api/users/%d/export" % self.signup["id"], headers=self.bearer).text
        for word in ("password_hash", "pw_salt", "share_secret", "token_hash", "loc_lat", "loc_lng"):
            self.assertNotIn(word, text, "导出里出现了敏感列 " + word)
        self.assertNotIn("opsother", text, "别人的账号被带进单用户导出")
        self.assertEqual(self.ops.get("/api/users/999999/export", headers=self.bearer).status_code, 404)

    def test_rename_user_needs_the_exact_username_and_leaves_an_audit_row(self):
        before = self.sql("SELECT nickname FROM users WHERE id=?", (self.signup["id"],))[0]["nickname"]
        wrong = self.ops.post("/api/users/%d/nickname" % self.signup["id"],
                              json={"expect_username": "写错的人", "nickname": "新昵称"},
                              headers=self.bearer)
        self.assertEqual(wrong.status_code, 409, "用户名对不上却改了昵称")
        self.assertEqual(self.sql("SELECT nickname FROM users WHERE id=?",
                                  (self.signup["id"],))[0]["nickname"], before,
                         "被拒的动作还是改了库")
        empty = self.ops.post("/api/users/%d/nickname" % self.signup["id"],
                              json={"expect_username": "opsowner", "nickname": "   "},
                              headers=self.bearer)
        self.assertEqual(empty.status_code, 422, "空昵称也能提交")
        long_name = "一二三四五六七八九十一二三四五六七八九十多出来的字"
        ok = self.ops.post("/api/users/%d/nickname" % self.signup["id"],
                           json={"expect_username": "opsowner", "nickname": long_name},
                           headers=self.bearer)
        self.assertEqual(ok.status_code, 200, ok.text)
        saved = self.sql("SELECT nickname FROM users WHERE id=?", (self.signup["id"],))[0]["nickname"]
        self.assertEqual(saved, long_name[:20], "昵称没有被截到 20 字")
        self.assertEqual(ok.json()["nickname"], saved, "回执与落库不一致")
        row = self.audits("rename_user")[-1]
        self.assertEqual(row["before_json"]["nickname"], before)
        self.assertEqual(row["after_json"]["nickname"], saved)
        # 另一个账号的昵称没被牵连
        self.assertNotEqual(self.sql("SELECT nickname FROM users WHERE id=?",
                                     (self.other["id"],))[0]["nickname"], saved)

    def test_orphan_media_counts_are_real_and_no_filenames_leak(self):
        up = self.root / "UPLOAD"
        (up / "keep-me.jpg").write_bytes(b"x" * 10)
        (up / "dm-keep.webm").write_bytes(b"z" * 20)
        (up / "orphan-one.png").write_bytes(b"y" * 33)
        self.sql("INSERT INTO posts(user_id,body,images,created_at) VALUES (?,?,?,?)",
                 (self.signup["id"], "带图帖子", json.dumps(["/uploads/keep-me.jpg"]),
                  "2026-10-19 00:00:00"))
        self.sql("INSERT INTO messages(conv_key,from_id,to_id,body,created_at,kind,media_name)"
                 " VALUES (?,?,?,?,?,?,?)",
                 ("1:2", self.signup["id"], self.other["id"], "", "2026-10-19 00:00:01",
                  "video", "dm-keep.webm"))
        r = self.ops.get("/api/media/orphans", headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        out = r.json()
        self.assertEqual(out["files"], 3, "上传目录里的文件数不对")
        self.assertEqual(out["referenced"], 2, "被帖子/私聊引用的文件没算进 referenced")
        self.assertEqual(out["orphans"], 1, "孤儿数不对")
        self.assertEqual(out["orphan_bytes"], 33, "孤儿体积算错了")
        text = r.text
        for name in ("keep-me.jpg", "dm-keep.webm", "orphan-one.png"):
            self.assertNotIn(name, text, "文件名属于敏感列，不该回给前端：" + name)
        self.assertIn("只报告", out["note"], "没有说明这是只读报告，运营会以为点一下就删")

    def test_dm_export_covers_only_that_pair_and_blanks_recalled_bodies(self):
        third = self.app.post("/api/register", json=dict(self.app_body, username="opsthird")).json()
        a, b, c = self.signup["id"], self.other["id"], third["id"]
        key = "%d:%d" % (min(a, b), max(a, b))
        other_key = "%d:%d" % (min(a, c), max(a, c))
        self.sql("INSERT INTO messages(conv_key,from_id,to_id,body,created_at,recalled_at)"
                 " VALUES (?,?,?,?,?,NULL)", (key, a, b, "第一句正常话", "2026-10-19 00:00:01"))
        self.sql("INSERT INTO messages(conv_key,from_id,to_id,body,created_at,recalled_at)"
                 " VALUES (?,?,?,?,?,?)", (key, b, a, "这句要撤回", "2026-10-19 00:00:02",
                                           "2026-10-19 00:00:03"))
        self.sql("INSERT INTO messages(conv_key,from_id,to_id,body,created_at,recalled_at)"
                 " VALUES (?,?,?,?,?,NULL)", (other_key, a, c, "不该出现在这段会话里",
                                              "2026-10-19 00:00:04"))
        self.assertEqual(self.ops.get("/api/users/%d/messages/export" % a,
                                      headers=self.bearer).status_code, 422,
                         "没给 with_user 也导出了")
        r = self.ops.get("/api/users/%d/messages/export" % a,
                         params={"with_user": b}, headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        out = r.json()
        self.assertEqual(len(out["messages"]), 2, "导出的条数不对：%d" % len(out["messages"]))
        bodies = [m["body"] for m in out["messages"]]
        self.assertIn("第一句正常话", bodies)
        self.assertNotIn("这句要撤回", r.text, "撤回的消息正文漏出来了")
        self.assertTrue(any(m["recalled"] for m in out["messages"]), "撤回标记丢了")
        self.assertNotIn("不该出现在这段会话里", r.text, "把第三个人的会话也导出来了")
        for word in ("password_hash", "pw_salt", "share_secret", "token_hash"):
            self.assertNotIn(word, r.text, "会话导出带出了凭据列 " + word)
        row = self.audits("export_dm")[-1]
        self.assertEqual(row["after_json"]["with_user"], b)
        self.assertEqual(row["after_json"]["messages"], 2)
        self.assertNotIn("第一句正常话", json.dumps(self.audits("export_dm"), ensure_ascii=False),
                         "会话正文落进审计了")

    def test_overview_counts_come_from_detail_tables_including_ones_directus_cannot_read(self):
        self.app.post("/api/weight/log", headers=self.auth(), json={"weight_jin": 151})
        out = self.ops.get("/api/overview", headers=self.bearer).json()
        for table in ("users", "posts", "comments", "post_likes", "follows", "messages", "feedback",
                      "water_logs"):
            real = self.sql("SELECT COUNT(*) c FROM %s" % table)[0]["c"]
            self.assertEqual(out["counts"][table], real, table + " 的看板数与明细表不一致")
        self.assertIn("ratio", out["region"])
        # 主应用联系不上时不许谎报：必须明写 unreachable
        self.assertIn("unreachable", json.dumps(out["keys"], ensure_ascii=False),
                      "拿不到 /health/ready 却给了个像样的密钥状态")

    def test_overview_reports_missing_table_as_none_not_zero(self):
        out = self.ops.get("/api/overview", headers=self.bearer).json()
        self.assertEqual(out["counts"]["water_logs"],
                         self.sql("SELECT COUNT(*) c FROM water_logs")[0]["c"])
        self.sql("DROP TABLE water_logs")
        out = self.ops.get("/api/overview", headers=self.bearer).json()
        self.assertIsNone(out["counts"]["water_logs"], "表不在了要说不知道，不许报 0")

    # ---- 门 ----
    def test_gate_only_rises_and_reports_what_the_app_says(self):
        g = self.ops.get("/api/gate", headers=self.bearer).json()
        self.assertEqual(g["effective"], 0)
        self.assertTrue(g["brake_on"])
        self.assertEqual(self.ops.post("/api/gate", json={"expect_current": 7, "new": 9},
                         headers=self.bearer).status_code, 409, "current 对不上还敢改")
        self.assertEqual(self.ops.post("/api/gate", json={"expect_current": 0, "new": 0},
                         headers=self.bearer).status_code, 400, "抬到 0 该走刹车")
        self.assertEqual(self.ops.post("/api/gate", json={"expect_current": 0, "new": -5},
                         headers=self.bearer).status_code, 400, "门被放下了")
        r = self.ops.post("/api/gate", json={"expect_current": 0, "new": 33}, headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(Path(self.ops_mod.MIN_BUILD_FILE).read_text().strip(), "33", "文件没落下去")
        self.assertIsNone(r.json()["reported_by_app"], "主应用联系不上时不许编一个生效值")
        self.assertEqual(self.ops.post("/api/gate", json={"expect_current": 33, "new": 30},
                         headers=self.bearer).status_code, 400, "抬上去之后还能放下来")

    def test_brake_requires_the_exact_phrase(self):
        self.ops.post("/api/gate", json={"expect_current": 0, "new": 33}, headers=self.bearer)
        self.assertEqual(self.ops.post("/api/brake", json={"phrase": "确定"},
                         headers=self.bearer).status_code, 409)
        self.assertEqual(Path(self.ops_mod.MIN_BUILD_FILE).read_text().strip(), "33")
        r = self.ops.post("/api/brake", json={"phrase": "放开全部客户端"}, headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(Path(self.ops_mod.MIN_BUILD_FILE).read_text().strip(), "0")

    # ---- 备份 ----
    def test_backup_failure_is_a_failure_not_a_200(self):
        Path(self.ops_mod.BACKUP_SCRIPT).write_text("raise SystemExit(3)\n", encoding="utf-8")
        r = self.ops.post("/api/backup", json={}, headers=self.bearer)
        self.assertEqual(r.status_code, 500, "备份脚本退出码 3，接口却当成功了")
        self.assertEqual(self.audits("backup")[-1]["note"], "脚本退出码 3", "失败没落到审计里")

    def test_backup_must_pass_integrity_check(self):
        script = Path(self.ops_mod.BACKUP_SCRIPT)
        script.write_text(
            "import sqlite3,os,time\n"
            "d=os.environ['QINGSU_BACKUP_DIR']\n"
            "p=os.path.join(d,'qingsu-'+time.strftime('%Y%m%d-%H%M%S')+'.db')\n"
            "s=sqlite3.connect(os.environ['QINGSU_DB']);t=sqlite3.connect(p)\n"
            "s.backup(t);t.close();s.close()\n"
            "with open(p,'r+b') as f: f.seek(4096); f.write(b'CORRUPT'*64)\n",
            encoding="utf-8")
        r = self.ops.post("/api/backup", json={}, headers=self.bearer)
        self.assertEqual(r.status_code, 500, "写坏的快照被判成 ok")
        self.assertIn("integrity", json.dumps(self.audits("backup")[-1], ensure_ascii=False))

    def test_backup_success_reports_the_snapshot_it_made(self):
        script = Path(self.ops_mod.BACKUP_SCRIPT)
        script.write_text(
            "import sqlite3,os,time\n"
            "d=os.environ['QINGSU_BACKUP_DIR']\n"
            "p=os.path.join(d,'qingsu-'+time.strftime('%Y%m%d-%H%M%S')+'.db')\n"
            "s=sqlite3.connect(os.environ['QINGSU_DB']);t=sqlite3.connect(p)\n"
            "s.backup(t);t.close();s.close()\n", encoding="utf-8")
        r = self.ops.post("/api/backup", json={}, headers=self.bearer)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["snapshot"].endswith(".db"))
        self.assertEqual(r.json()["integrity"], "ok")
        self.assertTrue((Path(self.ops_mod.BACKUP_DIR) / r.json()["snapshot"]).is_file())


class SeedContract(unittest.TestCase):
    """播种脚本的格式契约。这条是上线后由联动测试抓出来的真实故障：
    权限行的 fields 写成 JSON 数组时，Directus 会当成'一个字段都不许读'，
    运营账号只拿得到主键——接口全绿、后台实际上没法用。"""

    def test_fields_must_be_comma_separated_strings(self):
        src = (BACKEND / "directus" / "seed_policies.py").read_text(encoding="utf-8")
        self.assertIn('",".join(whitelist)', src, "读权限的 fields 没写成逗号分隔字符串")
        self.assertIn('",".join(fields)', src, "写权限的 fields 没写成逗号分隔字符串")
        self.assertNotIn("json.dumps(whitelist)", src, "又把 fields 写成 JSON 数组了")

    def test_seed_registers_collection_meta(self):
        """元数据不注册，控制台"内容"就是空的（实测：表在、接口能读、Studio 显示没有任何模型）。"""
        src = (BACKEND / "directus" / "seed_policies.py").read_text(encoding="utf-8")
        self.assertIn("directus_collections", src)
        self.assertIn("ensure_collection_meta", src)

    def test_every_write_listed_field_is_inside_the_read_whitelist(self):
        src = (BACKEND / "directus" / "seed_policies.py").read_text(encoding="utf-8")
        # 播种脚本运行时自己会校验（缺字段直接 SystemExit）；这里钉住那段校验没被删掉
        self.assertIn("sorted(missing)", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
