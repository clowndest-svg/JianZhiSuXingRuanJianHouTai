#!/usr/bin/env bash
# 后台控制台的一次性装配 + 可重跑自检。放在服务器上的 /opt/qingsu/admin-console/ 下执行。
# 幂等：跑第二次不会起两份容器、不会插出两条同名策略、不会重新生成密钥。
set -uo pipefail

BASE=/opt/qingsu/admin-console
ADMIN=/opt/qingsu/admin
DB=/opt/qingsu/data/qingsu.db
DATA_DIR=/opt/qingsu/data
SUPER_MAIL=ops@qingsu.app          # K-6：必须是能过 Directus 邮箱校验的地址，.local 会让 bootstrap 退 1
OPERATOR_MAIL=daily@qingsu.app
FAIL=0

say() { printf '%s %s\n' "$1" "$2"; }
bad() { FAIL=1; printf '红 %s\n' "$1"; }
good() { printf '绿 %s\n' "$1"; }

mkdir -p "$BASE" "$ADMIN"
chmod 700 "$ADMIN"

echo "== 1. 密钥文件（root:600，值永不打印）"
if [ -f "$ADMIN/console.json" ]; then
  say 已有 "console.json（不动它，换密钥会让所有人重新登录）"
else
  python3 - "$ADMIN/console.json" <<'PY'
import json, secrets, sys, os
path = sys.argv[1]
data = {"ops_token": secrets.token_hex(32),
        "cookie_secret": secrets.token_hex(32),
        "directus_key": secrets.token_hex(32),
        "directus_secret": secrets.token_hex(32),
        "super_admin_password": secrets.token_hex(16),
        "operator_password": secrets.token_hex(16),
        "super_admin_email": "ops@qingsu.app",
        "operator_email": "daily@qingsu.app",
        "basic_user": "qingsu",
        # Basic 口令缺了就会让运维台直接 503（宁可拒服也不静默敞开），所以这里必须生成
        "basic_password": secrets.token_urlsafe(24)}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(data, f)
print("已生成 %s（权限 600，值不落日志）" % path)
PY
  [ -f "$ADMIN/console.json" ] || bad "console.json 没生成"
fi
# 已有的 console.json 只补新键，绝不重新生成旧值（换 KEY 等于全站重新登录）
python3 - "$ADMIN/console.json" <<'PY'
import json, secrets, sys, os
path = sys.argv[1]
d = json.load(open(path, encoding="utf-8"))
added = []
for key, maker in (("basic_user", lambda: "qingsu"), ("basic_password", lambda: secrets.token_urlsafe(24))):
    if not d.get(key):
        d[key] = maker()
        added.append(key)
if added:
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.replace(tmp, path)
print("补了键：", added or "无（Basic 口令已存在）")
PY
chmod 600 "$ADMIN/console.json"

# compose 只吃 env 文件，所以从 json 现生成一份（每次重生成，保证和 json 一致）
python3 - "$ADMIN/console.json" "$ADMIN/directus.env" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
lines = ["DIRECTUS_KEY=%s" % d["directus_key"], "DIRECTUS_SECRET=%s" % d["directus_secret"],
         "DIRECTUS_ADMIN_EMAIL=%s" % d["super_admin_email"],
         "DIRECTUS_ADMIN_PASSWORD=%s" % d["super_admin_password"]]
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
PY
chmod 600 "$ADMIN/directus.env"
good "directus.env 已从 console.json 生成（600 root）"

echo "== 2. 数据目录权限（C-2b：第二个写入者要能建 -wal）"
echo "   改前：$(stat -c '%a %U:%G' "$DATA_DIR") / $(stat -c '%a %U:%G' "$DB")"
chown qingsu:qingsu "$DATA_DIR"
chmod 2770 "$DATA_DIR"          # setgid：容器新建的 -wal/-shm 自动落 group=qingsu（K-3）
chmod 660 "$DB"
for f in "$DATA_DIR"/qingsu.db-wal "$DATA_DIR"/qingsu.db-shm; do
  [ -e "$f" ] && chmod 660 "$f" && echo "   顺带放开 $(basename "$f")"
done
stat -c '   现在：%a %U:%G %n' "$DATA_DIR" "$DB"
[ "$(stat -c '%a' "$DATA_DIR")" = "2770" ] && [ "$(stat -c '%a' "$DB")" = "660" ] \
  && good "权限就位" || bad "权限没落到 2770/660"
systemctl is-active qingsu >/dev/null && good "主应用在这次改权限后仍然 active" \
  || bad "主应用不是 active —— 立刻回退：chmod 755 $DATA_DIR; chmod 644 $DB"

echo "== 3. 起 Directus（绑 docker 桥地址）"
# 先让 compose 自己判这份文件合不合法。上一轮我用脚本改 YAML，把 ports 那一行改没了，
# md5 双向都对、传过去的却是坏文件——校验和只证明"传对了"，不证明"内容对"。
if ! docker compose -f "$BASE/docker-compose.yml" --env-file "$ADMIN/directus.env" config -q; then
  bad "docker-compose.yml 不合法，拒绝 up（见上面 compose 的报错）"
  exit 1
fi
good "compose 文件结构合法"
docker rm -f qsp-probe >/dev/null 2>&1
docker compose -f "$BASE/docker-compose.yml" --env-file "$ADMIN/directus.env" up -d 2>&1 | tail -2
BIND=$(docker port qingsu-console 8055/tcp 2>/dev/null | head -1)
echo "   实际绑定：${BIND:-（没查到）}"
printf '%s' "$BIND" | grep -q '^172\.17\.0\.1' && good "端口绑在 docker 桥地址（nginx 够得到、公网进不来）" \
  || bad "端口绑定不是 172.17.0.1：$BIND"
code=000
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --noproxy '*' http://172.17.0.1:8055/server/ping)
  [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "200" ] && good "容器就绪 ping=200（第 ${i} 次轮询）" || bad "ping=$code，容器没就绪"
echo "   状态：$(docker inspect -f '{{.State.Status}} 重启={{.RestartCount}}' qingsu-console)"
echo "   内存：$(docker stats --no-stream --format '{{.MemUsage}}' qingsu-console)"
ACC=$(docker logs qingsu-console 2>&1 | grep -iE "EACCES|not read/writeable" | head -3)
if [ -z "$ACC" ]; then
  good "容器内部没有写权限报错（K-1 的形态）"
else
  bad "容器里有写权限报错：$ACC"
fi

echo "== 4. 播种策略与权限，然后重启让缓存失效"
QINGSU_DB="$DB" python3 "$BASE/seed_policies.py" | tail -12
docker restart -t 20 qingsu-console >/dev/null
code=000
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --noproxy '*' http://172.17.0.1:8055/server/ping)
  [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "200" ] && good "重启后 ping=200" || bad "重启后 ping=$code"

echo "== 5. 用 API 建/对齐运营账号（口令由 Directus 自己算 bcrypt）"
# 口令一律走 600 的临时载荷文件，不进命令行（ps 上会看得见 -d 的内容）
PAY=$(mktemp); chmod 600 "$PAY"; trap 'rm -f "$PAY"' EXIT
SUPER_PW=$(python3 -c "import json;print(json.load(open('$ADMIN/console.json'))['super_admin_password'])")
printf '{"email":"%s","password":"%s"}' "$SUPER_MAIL" "$SUPER_PW" > "$PAY"
AT=$(curl -s --noproxy '*' -X POST http://172.17.0.1:8055/auth/login -H 'Content-Type: application/json' \
     -d @"$PAY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('access_token',''))")
[ -n "$AT" ] && good "超管能登录（token 长度 ${#AT}，值不打印）" || bad "超管登录失败——检查 ADMIN_EMAIL 与 console.json 是否同一份"
RID=$(curl -s --noproxy '*' -H "Authorization: Bearer $AT" 'http://172.17.0.1:8055/roles?fields=id,name' \
      | python3 -c "import sys,json;print(next((r['id'] for r in json.load(sys.stdin).get('data') or [] if r['name']=='轻塑运营'),''))")
[ -n "$RID" ] && good "找到运营角色 $RID" || bad "运营角色不存在，seed 没跑成"
OP_PW=$(python3 -c "import json;print(json.load(open('$ADMIN/console.json'))['operator_password'])")
EXIST=$(curl -s --noproxy '*' -H "Authorization: Bearer $AT" "http://172.17.0.1:8055/users?search=$OPERATOR_MAIL&fields=id" \
        | python3 -c "import sys,json;d=json.load(sys.stdin).get('data') or [];print(d[0]['id'] if d else '')")
if [ -z "$EXIST" ]; then
  printf '{"first_name":"轻塑","last_name":"运营","email":"%s","password":"%s","role":"%s","status":"active"}' \
    "$OPERATOR_MAIL" "$OP_PW" "$RID" > "$PAY"
  NU=$(curl -s --noproxy '*' -X POST http://172.17.0.1:8055/users -H "Authorization: Bearer $AT" \
       -H 'Content-Type: application/json' -d @"$PAY" \
       | python3 -c "import sys,json;d=json.load(sys.stdin);print((d.get('data') or {}).get('id') or d)")
  say 建号 "$NU"
else
  printf '{"password":"%s","role":"%s","status":"active"}' "$OP_PW" "$RID" > "$PAY"
  curl -s --noproxy '*' -X PATCH "http://172.17.0.1:8055/users/$EXIST" -H "Authorization: Bearer $AT" \
    -H 'Content-Type: application/json' -d @"$PAY" -o /dev/null -w '对齐账号 HTTP=%{http_code}\n'
fi
rm -f "$PAY"

echo "== 6. 权限真值验证（这一步不算数就别对外说后台做好了）"
printf '{"email":"%s","password":"%s"}' "$OPERATOR_MAIL" "$OP_PW" > "$PAY"
chmod 600 "$PAY"
DT=$(curl -s --noproxy '*' -X POST http://172.17.0.1:8055/auth/login -H 'Content-Type: application/json' \
     -d @"$PAY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('access_token',''))")
rm -f "$PAY"
[ -n "$DT" ] && good "运营账号能登录（token 长度 ${#DT}）" || bad "运营账号登不进去——下面的权限探针全都不算数"

# clean 的含义是"真的读到了行，而且行里没有敏感列"。
# 只看"响应里搜不到 password_hash"是假的：没授权时返回的是错误体，同样搜不到——上一轮就这么绿过。
probe() {
  local name="$1" url="$2" want="$3" body rows secret
  body=$(curl -s --noproxy '*' -H "Authorization: Bearer $DT" "$url")
  case "$want" in
    deny)
      printf '%s' "$body" | grep -q 'FORBIDDEN' && good "$name 被拒（默认拒绝成立）" \
        || bad "$name 竟然给了数据：$(printf '%s' "$body" | head -c 120)" ;;
    allow)
      printf '%s' "$body" | grep -q '"data"' && good "$name 读到了数据" \
        || bad "$name 读不到：$(printf '%s' "$body" | head -c 140)" ;;
    clean)
      rows=$(printf '%s' "$body" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print(-1); raise SystemExit
data = d.get('data')
print(len(data) if isinstance(data, list) else -1)
" 2>/dev/null)
      secret=$(printf '%s' "$body" | grep -oE '"(password_hash|pw_salt|share_secret|token_hash|loc_lat|loc_lng|code_hash|email_hash|photo_url|images|mem_value|answer)"' | sort -u | tr '\n' ',')
      if [ "$rows" = "-1" ]; then
        bad "$name 没读到任何行（权限没落地或被拒），这条不能算'干净'：$(printf '%s' "$body" | head -c 120)"
      elif [ -n "$secret" ]; then
        bad "$name 读到 $rows 行但带出了敏感列 $secret"
      else
        good "$name 读到 $rows 行，且没有敏感列"
      fi ;;
  esac
}
if [ -n "$DT" ]; then
  probe "运营读 users 全字段" "http://172.17.0.1:8055/items/users?limit=5&fields=*" clean
  probe "运营显式要 password_hash" "http://172.17.0.1:8055/items/users?fields=id,password_hash" clean
  probe "运营读 feedback" "http://172.17.0.1:8055/items/feedback?limit=3&fields=id,status,body" allow
  probe "运营读 profiles" "http://172.17.0.1:8055/items/profiles?limit=3&fields=*" clean
  probe "运营读 sessions" "http://172.17.0.1:8055/items/sessions?limit=3&fields=*" clean
  # messages 是"授权可读"的（docs/01 M-40 合规读取），拿它当默认拒绝的反例是我自己写错了期望。
  # 不带 fields 的请求只回主键（K-9），所以这里要显式点字段才算真读到内容。
  probe "运营读 messages（合规读取，授权内）" "http://172.17.0.1:8055/items/messages?limit=2&fields=id,conv_key,read_at" clean
  probe "运营读 directus_users（系统表，不该授权）" "http://172.17.0.1:8055/items/directus_users?limit=1" deny
  probe "运营读 follows（平台读不了）" "http://172.17.0.1:8055/items/follows?limit=1" deny
  # 已知敞口要量出来，不要假装不存在（docs/03 L3）：超管绕过一切字段权限。
  # 这条不是"通过"，是把残余风险钉成一条能复测的记录。
  LEAK=$(curl -s --noproxy '*' -H "Authorization: Bearer $AT" 'http://172.17.0.1:8055/items/users?limit=1&fields=*' \
         | grep -oE '"(password_hash|pw_salt|share_secret|token_hash|token)"' | sort -u | tr '\n' ' ')
  say 已知敞口 "超管 fields=* 带出敏感列：${LEAK:-（无）}（口令只落 root:600、日常不用超管、外层还有 BasicAuth）"
fi

echo "== 7. 后台是旁路：容器停掉主应用照常"
docker stop -t 15 qingsu-console >/dev/null
curl -s --noproxy '*' -o /dev/null -w '   主应用 /health/ready HTTP=%{http_code}\n' http://172.17.0.1:8000/health/ready
docker start qingsu-console >/dev/null
for i in $(seq 1 60); do code=$(curl -s -o /dev/null -w '%{http_code}' --noproxy '*' http://172.17.0.1:8055/server/ping); [ "$code" = "200" ] && break; sleep 2; done
[ "$code" = "200" ] && good "容器重启完毕，后台回来了" || bad "容器重启失败 ping=$code"

echo "== 8. 生产库与账号未被触动"
echo "   用户数：$(sqlite3 "$DB" 'SELECT COUNT(*) FROM users')  完整性：$(sqlite3 "$DB" 'PRAGMA integrity_check')"
DTABLES=$(sqlite3 "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'directus_%'")
echo "   directus 表数：$DTABLES"
echo "   admin_audit：$(sqlite3 "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE name='admin_audit'")（运维 API 起服务时建）"
echo "   数据目录归属：$(stat -c '%a %U:%G' "$DATA_DIR") / $(stat -c '%a %U:%G' "$DB")"
echo "   密钥仍在挂载点之外：$(ls /opt/qingsu/keys | tr '\n' ' ')"

echo
[ "$FAIL" = "0" ] && echo "BOOTSTRAP_OK" || echo "BOOTSTRAP_HAS_FAILURES"
exit "$FAIL"
