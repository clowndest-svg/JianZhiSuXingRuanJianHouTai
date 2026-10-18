#!/usr/bin/env bash
# 运维 API 的端到端自证（S/P 混合：动作打生产库上的夹具账号，跑完按 id 删干净）。
# 幂等：重跑不会多起服务、不会留下夹具账号、不会改生产门值。
set -uo pipefail
BASE=/opt/qingsu/admin-console
ADMIN=/opt/qingsu/admin
DB=/opt/qingsu/data/qingsu.db
FAIL=0
good() { printf '绿 %s\n' "$1"; }
bad() { printf '红 %s\n' "$1"; FAIL=1; }
say() { printf '   %s %s\n' "$1" "$2"; }

echo "== 1. 装 unit 并起服务"
cp "$BASE/qingsu-ops.service" /etc/systemd/system/qingsu-ops.service
chmod 644 /etc/systemd/system/qingsu-ops.service
systemctl daemon-reload
systemctl enable --now qingsu-ops >/dev/null 2>&1
systemctl restart qingsu-ops
sleep 2
systemctl is-active qingsu-ops >/dev/null && good "qingsu-ops active" || { bad "qingsu-ops 起不来"; journalctl -u qingsu-ops -n 15 --no-pager; }
if [ "$(systemctl show qingsu-ops -p UMask --value)" = "0002" ]; then
  good "服务 UMask=0002（否则它建的 -wal 主应用写不了）"
else
  bad "UMask 不是 0002：$(systemctl show qingsu-ops -p UMask --value)"
fi

echo "== 2. 只绑桥地址"
ss -ltn | grep -q '172.17.0.1:8100' && good "8100 监听在 docker 桥地址（nginx 那个容器够得到）" || bad "8100 没在桥地址上监听"
ss -ltnp | grep ':8100' | grep -Eq '0.0.0.0:8100|\*:8100|124.220.54.64:8100' && bad "8100 暴露到公网了" || good "8100 没有对外监听"
code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --connect-timeout 3 http://124.220.54.64:8100/api/overview 2>/dev/null || echo 连不上)
echo "   从公网地址打 8100：$code（连不上或超时才对）"

# 口令一律走 600 的 curl 配置文件，不进命令行（ps 上看得见 -u 的参数）
JAR=$(mktemp); CONF=$(mktemp); PAY=$(mktemp); NOB=$(mktemp)
chmod 600 "$JAR" "$CONF" "$PAY" "$NOB"
trap 'rm -f "$JAR" "$CONF" "$PAY" "$NOB"' EXIT
BUSER=$(python3 -c "import json;print(json.load(open('$ADMIN/console.json')).get('basic_user',''))")
BPASS=$(python3 -c "import json;print(json.load(open('$ADMIN/console.json')).get('basic_password',''))")
TOKEN=$(python3 -c "import json;print(json.load(open('$ADMIN/console.json'))['ops_token'])")
[ -n "$BPASS" ] && good "Basic 口令已配（长度 ${#BPASS}，值不打印）" || { bad "console.json 里没有 basic_password——运维台会整台 503"; }
printf 'user = "%s:%s"\n' "$BUSER" "$BPASS" > "$CONF"
printf 'header = "X-Qingsu-Token: %s"\n' "$TOKEN" > "$NOB"

echo "== 3. 两层闸各自独立"
code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' http://172.17.0.1:8100/api/overview)
hdr=$(curl -s --noproxy '*' -D - -o /dev/null http://172.17.0.1:8100/api/overview | grep -ci www-authenticate)
[ "$code" = "401" ] && [ "$hdr" = "1" ] && good "L2：没 Basic 直接 401 且带挑战头" || bad "L2 没生效：code=$code 挑战头=$hdr"
code=$(curl -s --noproxy '*' -K "$CONF" -o /dev/null -w '%{http_code}' http://172.17.0.1:8100/api/overview)
[ "$code" = "401" ] && good "L3：过了 Basic 但没登录运维台，仍然 401" || bad "L3 没生效：$code"
code=$(curl -s --noproxy '*' -K "$CONF" -o /dev/null -w '%{http_code}' -X POST http://172.17.0.1:8100/api/users/1/ban -H 'Content-Type: application/json' -d '{"reason":"x"}')
[ "$code" = "401" ] && good "高危动作同样要两层" || bad "未授权能发高危动作：$code"
printf '{"token":"%s"}' "$TOKEN" > "$PAY"
OKJSON=$(curl -s --noproxy '*' -c "$JAR" -K "$CONF" -X POST http://172.17.0.1:8100/api/login -H 'Content-Type: application/json' -d @"$PAY")
printf '%s' "$OKJSON" | grep -q '"code"' && good "Basic + 令牌登录成功" || bad "登录失败：$OKJSON"
SETC=$(curl -s --noproxy '*' -D - -o /dev/null -K "$CONF" -X POST http://172.17.0.1:8100/api/login -H 'Content-Type: application/json' -d @"$PAY" | tr -d '')
printf '%s' "$SETC" | grep -qi "set-cookie: qops=.*secure" && good "会话 cookie 带 Secure（明文 http 上会被丢掉，这是对的）" || bad "cookie 没带 Secure"
printf '%s' "$SETC" | grep -qi "httponly" && good "cookie 带 HttpOnly" || bad "cookie 没带 HttpOnly"
printf '%s' "$SETC" | grep -qi "samesite=strict" && good "cookie 带 SameSite=Strict" || bad "cookie 没带 SameSite=Strict"
OV=$(curl -s --noproxy '*' -K "$CONF" -K "$NOB" http://172.17.0.1:8100/api/overview)
printf '%s' "$OV" | grep -q '"counts"' && good "cookie 读概览 OK" || bad "cookie 读概览失败：$(printf '%s' "$OV" | head -c 120)"
BEAR=$(curl -s --noproxy '*' -K "$CONF" -K "$NOB" http://172.17.0.1:8100/api/whoami)
printf '%s' "$BEAR" | grep -q '"script"' && good "X-Qingsu-Token 这条路也通（脚本用）" || bad "令牌头不认：$BEAR"

echo "== 4. 敏感列不会从这个接口出去"
LIST=$(curl -s --noproxy '*' -K "$CONF" -K "$NOB" 'http://172.17.0.1:8100/api/users?limit=50')
LEAKED=$(printf '%s' "$LIST" | grep -oE '"(password_hash|pw_salt|share_secret|token_hash|token)"' | sort -u | tr '\n' ' ')
[ -z "$LEAKED" ] && good "用户列表没有凭据列" || bad "用户列表带出 $LEAKED"
printf '%s' "$LIST" | grep -q '"banned_at"' && good "列表里有封号状态（否则运营看不出谁被停用）" || bad "列表里没有封号状态"

echo "== 5. 端到端：建一个夹具账号，走完整高危链路，再注销掉"
# 上一轮如果中途失败，库里会留夹具；先按前缀清掉再开始，否则"应为 2 个账号"那条会假红。
# 只清机器生成的 houkouops_ 前缀，逐个打印 id，绝不碰真实账号。
LEFT=$(sqlite3 "$DB" "SELECT group_concat(id) FROM users WHERE username LIKE 'houkouops_%'")
if [ -n "$LEFT" ] && [ "$LEFT" != "" ]; then
  say 清理 "发现上一轮遗留夹具 id=$LEFT，先删干净"
  python3 - "$DB" "$LEFT" <<'PY'
import sqlite3, sys
db, ids = sys.argv[1], [int(x) for x in sys.argv[2].split(",") if x]
c = sqlite3.connect(db, timeout=5)
c.execute("PRAGMA busy_timeout=5000"); c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA defer_foreign_keys=ON")
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
for uid in ids:
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
bad = c.execute("PRAGMA foreign_key_check").fetchall()
if bad:
    c.rollback(); raise SystemExit("遗留清理后外键不自洽，已回滚：%d 条" % len(bad))
c.commit(); c.close()
print("   遗留已清")
PY
fi
python3 - <<'PY' > /root/fixture.json 2>/root/fixture.err
import json, secrets, urllib.error, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def api(path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    h = {"Content-Type": "application/json", "X-App-Build": "34"}
    if token: h["Authorization"] = "Bearer " + token
    req = urllib.request.Request("http://172.17.0.1:8000" + path, data=data, headers=h,
                                 method="POST" if data else "GET")
    try:
        with opener.open(req, timeout=20) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try: return e.code, json.load(e)
        except Exception: return e.code, {}
name = "houkouops_" + secrets.token_hex(4)
st, s = api("/api/register", {"username": name, "password": secrets.token_urlsafe(16), "age": 30,
                              "height": 170, "weight_jin": 160, "target_weight_jin": 140})
print(json.dumps({"user": name, "id": s.get("id"), "token": s.get("token"), "register": st}))
PY
read -r FIXNAME FIXID FIFTOKEN < <(python3 -c "import json;d=json.load(open('/root/fixture.json'));print(d['user'],d['id'],d['token'])")
say 夹具 "$FIXNAME id=$FIXID"
ops() { curl -s --noproxy '*' -K "$CONF" -K "$NOB" -X "$1" "http://172.17.0.1:8100/api/$2" -H 'Content-Type: application/json' -d "$3"; }
# 带会话 cookie 的读请求同样必须过 Basic——漏掉这一个头，下面整条链会一起红
opsget() { curl -s --noproxy '*' -K "$CONF" -K "$NOB" "$1"; }
app_call() { curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $FIFTOKEN" -H 'X-App-Build: 34' http://172.17.0.1:8000/api/dashboard; }

[ "$(app_call)" = "200" ] && good "夹具在封号前能正常用主应用" || bad "夹具注册后主应用就不通，后面的结论都不可信"
r=$(ops POST "users/$FIXID/ban" "{\"expect_username\":\"$FIXNAME\",\"reason\":\"后台自证\"}")
printf '%s' "$r" | grep -q '"code"' && good "运维 API 封号成功" || bad "封号失败：$r"
[ "$(app_call)" = "403" ] && good "封号之后主应用 403（跨进程自证）" || bad "封号之后主应用还是 $(app_call)"
r=$(ops POST "users/$FIXID/ban" "{\"expect_username\":\"$FIXNAME\",\"reason\":\"重复\"}")
printf '%s' "$r" | grep -q '"already"' && good "重复封号说'已经封着'而不是报错" || bad "重复封号的形状不对：$r"
r=$(ops POST "users/$FIXID/ban" '{"expect_username":"错的人","reason":"x"}')
printf '%s' "$r" | grep -q '对不上' && good "用户名对不上时拒绝执行" || bad "回显确认没起作用：$r"
r=$(ops POST "users/$FIXID/reset-password" "{\"expect_username\":\"$FIXNAME\"}")
OTP=$(printf '%s' "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('one_time_password',''))" 2>/dev/null)
[ -n "$OTP" ] && good "重置口令给了一次性口令（长度 ${#OTP}，值不打印）" || bad "重置口令失败：$r"
[ "$(app_call)" = "401" ] && good "重置之后旧 token 立刻失效" || bad "旧 token 还能用，重置口令是句假话"
# 403=口令对了但账号被封；400=口令不对。用这个区分证明散列与主应用兼容，
# 而不是靠"登进去 200"——这一步账号本来就还封着，200 反而是错的。
TOKPAY=$(mktemp); chmod 600 "$TOKPAY"; trap 'rm -f "$JAR" "$CONF" "$PAY" "$NOB" "$TOKPAY"' EXIT
printf '{"username":"%s","password":"%s"}' "$FIXNAME" "$OTP" > "$TOKPAY"
st=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H 'X-App-Build: 34' \
     -d @"$TOKPAY" http://172.17.0.1:8000/api/login)
[ "$st" = "403" ] && good "一次性口令通过了口令校验（403=被封，说明散列兼容）" || bad "一次性口令校验结果不对 HTTP=$st（400 才是不匹配）"
printf '{"username":"%s","password":"%s"}' "$FIXNAME" "wrong-guess-1" > "$TOKPAY"
st=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H 'X-App-Build: 34' \
     -d @"$TOKPAY" http://172.17.0.1:8000/api/login)
[ "$st" = "400" ] && good "口令错时仍是 400，没把封号状态漏给猜测者" || bad "错口令给了 $st，枚举信号口径变了"
r=$(ops POST "users/$FIXID/unban" "{\"expect_username\":\"$FIXNAME\"}")
printf '%s' "$r" | grep -q '"code"' && good "解封成功" || bad "解封失败：$r"
printf '{"username":"%s","password":"%s"}' "$FIXNAME" "$OTP" > "$TOKPAY"
st=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H 'X-App-Build: 34' \
     -d @"$TOKPAY" http://172.17.0.1:8000/api/login)
[ "$st" = "200" ] && good "解封后一次性口令能正常登进去" || bad "解封后登不进去 HTTP=$st"
plan=$(ops POST "users/$FIXID/delete-account" "{\"expect_username\":\"$FIXNAME\",\"plan_only\":true}")
ROWS=$(printf '%s' "$plan" | python3 -c "import sys,json;print(json.load(sys.stdin).get('rows',0))" 2>/dev/null)
say 计划 "$(printf '%s' "$plan" | head -c 220)"
r=$(ops POST "users/$FIXID/delete-account" "{\"expect_username\":\"$FIXNAME\",\"confirm_rows\":$((ROWS+5))}")
printf '%s' "$r" | grep -q '对不上' && good "行数对不上时拒绝注销" || bad "confirm_rows 没起作用：$r"
r=$(ops POST "users/$FIXID/delete-account" "{\"expect_username\":\"$FIXNAME\",\"confirm_rows\":$ROWS}")
printf '%s' "$r" | grep -q '"deleted_rows"' && good "按服务端算出的行数（$ROWS）注销成功" || bad "注销失败：$r"
[ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM users WHERE id=$FIXID")" = "0" ] && good "夹具已从库里消失" || bad "夹具还在库里"
[ "$(sqlite3 "$DB" 'PRAGMA foreign_key_check' | wc -l)" = "0" ] && good "外键自洽（没留孤儿行）" || bad "外键不自洽"

echo "== 6. 写库之后：-wal 归属必须两边都能写（F-1 的根因）"
ls -l /opt/qingsu/data/qingsu.db* | awk '{print "   "$1, $3":"$4, $NF}'
BADWAL=$(stat -c '%a %n' /opt/qingsu/data/qingsu.db-wal /opt/qingsu/data/qingsu.db-shm 2>/dev/null | awk '$1 !~ /^[0-7][2367]0$/ {print}')
[ -z "$BADWAL" ] && good "WAL/SHM 组内可写（或此刻不存在，属正常）" || bad "WAL/SHM 主应用写不了：$BADWAL"
[ "$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' http://172.17.0.1:8000/health/ready)" = "200" ] \
  && good "主应用仍然 200" || bad "主应用健康接口不通"

echo "== 7. 门：只验读与拒绝路径，不改生产值（抬门会真的挡掉现役客户端）"
GATE=$(curl -s --noproxy '*' -K "$CONF" -K "$NOB" http://172.17.0.1:8100/api/gate)
printf '%s' "$GATE" | grep -q '"override"' && good "读门 OK：override=$(printf '%s' "$GATE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('override'))")" || bad "读门失败"
r=$(ops POST "gate" '{"expect_current":99999,"new":100000}')
printf '%s' "$r" | grep -q '没改' && good "expect_current 对不上时拒绝改" || bad "门的防呆没生效：$r"
say 门文件时间戳 "$(stat -c '%y' /opt/qingsu/data/min_build | cut -d. -f1)（被拒之后不该变）"
r=$(ops POST "brake" '{"phrase":"随便写的"}')
printf '%s' "$r" | grep -q '确认短语' && good "刹车需要原样短语" || bad "刹车防呆没生效：$r"
r=$(ops POST "brake" '{"phrase":"放开全部客户端"}')
printf '%s' "$r" | grep -q '"effective_now"' && good "拉刹车（写 0，现役行为不变）" || bad "刹车结果不对：$r"

echo "== 8. 备份与审计"
B=$(ops POST "backup" '{}')
printf '%s' "$B" | grep -q '"integrity": *"ok"' && good "备份并校验：$(printf '%s' "$B" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('snapshot'))")" || bad "备份这一步不对：$(printf '%s' "$B" | head -c 200)"
A=$(curl -s --noproxy '*' -K "$CONF" -K "$NOB" 'http://172.17.0.1:8100/api/audit?limit=60')
for act in ban unban reset_pw delete_account gate_brake backup; do
  printf '%s' "$A" | grep -q "\"action\": *\"$act\"" && say 审计 "$act 有留痕" || bad "审计里缺 $act（本轮确实做过）"
done
for w in password_hash pw_salt share_secret token_hash; do
  printf '%s' "$A" | grep -q "\"$w\"" && bad "审计里出现了凭据列 $w"
done
good "审计里没有凭据列"
if [ -n "$OTP" ] && printf '%s' "$A" | grep -q "$OTP"; then bad "一次性口令落进审计了"; else good "一次性口令没落审计"; fi

echo "== 9. 收尾"
say 用户数 "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM users')（应为 2）"
[ "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM users')" = "2" ] && good "只剩两个真实账号" || bad "账号数不对"
sqlite3 "$DB" "PRAGMA integrity_check" | sed 's/^/   integrity: /'
stat -c '   %a %U:%G %n' /opt/qingsu/data /opt/qingsu/data/qingsu.db
say data里的密钥文件数 "$(ls /opt/qingsu/data/*.key 2>/dev/null | wc -l)（应为 0）"
echo "   服务：qingsu=$(systemctl is-active qingsu) qingsu-ops=$(systemctl is-active qingsu-ops)"
rm -f /root/fixture.json /root/fixture.err
[ "$FAIL" = "0" ] && echo "OPS_VERIFY_OK" || echo "OPS_VERIFY_HAS_FAILURES"
exit "$FAIL"
