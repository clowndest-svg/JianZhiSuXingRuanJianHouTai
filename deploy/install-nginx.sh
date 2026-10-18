#!/usr/bin/env bash
# 把后台的两条前缀拼进现役 nginx 配置。失败就自动回滚，并且绝不换 inode。
set -uo pipefail
CONF=/opt/qingsu/tls/default.conf
SNIP=/opt/qingsu/admin-console/nginx-admin.conf
MARKER="后台管理系统（qingsu-admin-console）"
BK=/opt/qingsu/backups/nginx-tls-$(date +%Y%m%d-%H%M%S).conf
FAIL=0
good() { printf '绿 %s\n' "$1"; }
bad() { printf '红 %s\n' "$1"; FAIL=1; }

cp -a "$CONF" "$BK" && echo "   备份：$BK ($(md5sum "$BK" | cut -c1-12))"
INODE_BEFORE=$(stat -c %i "$CONF")
# 80 端口上那两份清单与 /ws/ 是被牵连风险最高的三样东西，先取基线
SHA_LJ_BEFORE=$(curl -s --noproxy '*' http://124.220.54.64/latest.json | sha256sum | cut -c1-16)
SHA_LE_BEFORE=$(curl -s --noproxy '*' http://124.220.54.64/latest-extensions.json | sha256sum | cut -c1-16)
HEALTH_BEFORE=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' https://127.0.0.1/health/ready -k)

echo "== 0. 前置条件：现役配置得先是"完整的"配置"
# 这一步是给我自己补的刹车：上一轮我用"最旧的那份备份"还原，把 /ws/ 段一起带走了，
# 私信实时通道当场就断了。装后台之前先确认现役配置里该有的都在。
grep -q "location /ws/" "$CONF" && good "现役配置里有 /ws/ 段" \
  || { bad "现役配置里没有 /ws/ 段——先修好主链路再来装后台，别在这里叠加改动"; exit 1; }
grep -q "proxy_http_version 1.1" "$CONF" && good "/ws/ 的 Upgrade 转发在" || { bad "/ws/ 段不完整"; exit 1; }
grep -q "client_max_body_size" "$CONF" && good "上传体积限制在" || bad "client_max_body_size 不见了"

echo "== 0b. 路径冲突预检：Directus 的 API 前缀不能是主应用已经占用的"
# 这些前缀一旦代理过去，主应用以后新增同名路由就会被后台静默抢走流量，所以先逐个问一遍。
CLASH=""
for p in auth/login items/posts collections fields schema server/ping users roles policies \
         permissions presets relations flows notifications folders files dashboards panels \
         translations settings extensions assets specification; do
  code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "http://172.17.0.1:8000/$p")
  [ "$code" = "404" ] || CLASH="$CLASH $p=$code"
done
if [ -n "$CLASH" ]; then
  bad "主应用已经占了这些路径，代理过去会抢它的流量：$CLASH"
  exit 1
fi
good "30 个前主应用全部返回 404，代理不会抢它的流量"

# 幂等判据不能用注释行：插入时注释会被一起带过去，但换个版本就可能没有那行注释。
if grep -q "zone=adminpage" "$CONF"; then
  echo "   已装过，跳过写入（幂等）"
else
  python3 - "$CONF" "$SNIP" <<'PY'
import io, re, sys
conf_path, snip_path = sys.argv[1], sys.argv[2]
raw = io.open(snip_path, encoding="utf-8").read().splitlines(True)
split = next(i for i, line in enumerate(raw) if "server 上下文" in line)
zones = "".join(raw[:split])          # 注释也保留：它们解释了"为什么不是 Basic、为什么还要代理根路径"
inside = "".join(raw[split + 1:])
text = io.open(conf_path, encoding="utf-8").read()
# limit_req_zone 只能在 http 上下文：拼到 server{ 之前，不是往里塞。
# 这份现役配置的 server{ 就在文件第一行（前面没有换行），所以必须按"行首"找，
# 不能只找 "\nserver {"——上一版就是这么在写盘之前停住的。
m = re.search(r"^(server[ \t]*\{)", text, re.M)
assert m, "看不懂这份配置的形状（找不到 server{ 的行首），不敢自动改"
assert "\n    location / {" in text, "找不到 location / 的插入锚点"
text = text[:m.start()] + zones + "\n" + text[m.start():]
anchor = "    location / {"
text = text.replace(anchor, inside + anchor, 1)
# 原地截断写：换成新 inode 的话，bind 挂载的容器还在看旧文件，
# nginx -t 与 reload 都会"成功"，线上却是老配置（现役 deploy.py 就是这么写的）
with io.open(conf_path, "w", encoding="utf-8") as f:
    f.write(text)
print("   已写入 %d 字节（zones 在 server 外，location 在 server 内）" % len(text))
PY
fi

INODE_AFTER=$(stat -c %i "$CONF")
[ "$INODE_BEFORE" = "$INODE_AFTER" ] && good "inode 未变（容器看到的就是这一份）" \
  || bad "inode 变了：$INODE_BEFORE -> $INODE_AFTER，容器还在用旧文件，必须 docker restart"

if ! docker exec qingsu-tls nginx -t > /tmp/nginx-t.log 2>&1; then
  bad "nginx -t 不过，回滚：$(tail -2 /tmp/nginx-t.log | tr '\n' ' ')"
  cat "$BK" > "$CONF"
  docker exec qingsu-tls nginx -t > /dev/null 2>&1 || bad "回滚后配置仍然不过——需要人工介入"
  exit 1
fi
good "nginx -t 通过"
docker exec qingsu-tls nginx -s reload
sleep 3

echo "== 独立回读（不看 reload 有没有报错，看线上真实行为）"
docker exec qingsu-tls nginx -T 2>/dev/null | grep -q "adminpage" && good "nginx -T 里查得到新加的限流域" || bad "线上配置里没有这段"
docker exec qingsu-tls nginx -T 2>/dev/null | grep -A6 "location /ws/" | grep -q "proxy_http_version 1.1" \
  && good "/ws/ 的 Upgrade 三件套还在" || bad "/ws/ 被碰坏了（私信会静默降级）"
HEALTH_AFTER=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' https://127.0.0.1/health/ready -k)
[ "$HEALTH_AFTER" = "200" ] && good "主应用经 https 仍然 200（改前 $HEALTH_BEFORE）" || bad "主应用经 https 变成 $HEALTH_AFTER"
SHA_LJ_AFTER=$(curl -s --noproxy '*' http://124.220.54.64/latest.json | sha256sum | cut -c1-16)
SHA_LE_AFTER=$(curl -s --noproxy '*' http://124.220.54.64/latest-extensions.json | sha256sum | cut -c1-16)
[ "$SHA_LJ_BEFORE" = "$SHA_LJ_AFTER" ] && good "latest.json 未受影响" || bad "latest.json 变了：$SHA_LJ_BEFORE -> $SHA_LJ_AFTER"
[ "$SHA_LE_BEFORE" = "$SHA_LE_AFTER" ] && good "latest-extensions.json 未受影响" || bad "清单变了"

echo "== 主应用自己的路由经过新配置之后仍然归它自己（防止代理抢流量）"
check_route() {  # 说明 路径 期望码
  local label="$1" path="$2" want="$3"
  local code; code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -k "https://127.0.0.1$path")
  [ "$code" = "$want" ] && good "$label $path → $code" || bad "$label $path → $code（期望 $want）"
}
check_route "首页" / 200
check_route "版本清单" /version.json 200
check_route "安装包" /qingsu.apk 200
check_route "业务接口仍走主应用（未登录应 401，不是后台的 403/404）" /api/dashboard 401
check_route "分享页缺参数时由主应用做校验（422=主应用在答）" /api/public/dashboard 422
check_route "样式表" /style.css 200

echo "== 后台前缀对外行为"
code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -k https://127.0.0.1/admin/)
[ "$code" = "200" ] && good "/admin/ 经 https 可达（$code）" || bad "/admin/ = $code"
body=$(curl -s --noproxy '*' -k https://127.0.0.1/admin/)
printf '%s' "$body" | grep -q '<base href="/admin/"' && good "Data Studio 的 base 正确（不是 /admin/admin/）" || bad "base 不对：$(printf '%s' "$body" | grep -oE '<base[^>]*>')"
asset=$(printf '%s' "$body" | grep -oE 'src="\./assets/[^"]+"' | head -1 | sed 's/src=".\/assets\///; s/"$//')
[ -n "$asset" ] && code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -k "https://127.0.0.1/admin/assets/$asset") \
  && echo "   入口资源 /admin/assets/$asset → HTTP ${code}"
[ "${code:-0}" = "200" ] && good "后台静态资源经 nginx 能取到（子路径这条路真的通）" || bad "子路径资源取不到（HTTP ${code:-未测}）"
code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -k https://127.0.0.1/ops/)
[ "$code" = "401" ] && good "/ops/ 没口令直接 401（Basic 这层生效）" || bad "/ops/ = $code，外层闸没生效"
hdr=$(curl -s --noproxy '*' -D - -o /dev/null -k https://127.0.0.1/ops/ | grep -i www-authenticate)
[ -n "$hdr" ] && good "401 带挑战头：$(printf '%s' "$hdr" | tr -d '\r')" || bad "没带 WWW-Authenticate，浏览器不会弹框"
code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -k https://127.0.0.1/admin)
[ "$code" = "301" ] && good "/admin 会跳到 /admin/" || bad "/admin = $code"

echo "== 限流真的会咬（爆破登录口不该比刷页面便宜）"
codes=""
for i in $(seq 1 14); do codes="$codes$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -k -X POST https://127.0.0.1/auth/login \
  -H 'Content-Type: application/json' -d '{"email":"nobody@qingsu.app","password":"x"}') "; done
echo "   连打 14 次 /auth/login：$codes"
printf '%s' "$codes" | grep -q "503\|429" && good "超额的登录请求被限住了" || bad "限流没生效（全是放行）"

[ "$FAIL" = "0" ] && echo "NGINX_ADMIN_OK" || echo "NGINX_ADMIN_HAS_FAILURES"
exit "$FAIL"
