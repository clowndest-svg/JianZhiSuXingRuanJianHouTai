#!/usr/bin/env bash
# 三个 helper 的仓库侧判据：把参数校验与写门函数抽出来喂正反样本，证明命令注入与路径穿越进不去。
# 纯逻辑，不依赖 systemd / docker / root，本机 bash 就能跑。
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
HELPERS="$HERE/qingsu-ops-helpers"
FAIL=0
GOODS=0
good() { GOODS=$((GOODS+1)); printf '绿 %s\n' "$1"; }
bad() { FAIL=1; printf '红 %s\n' "$1"; }

for helper in qingsu-backup qingsu-set-gate qingsu-container-health; do
  file="$HELPERS/$helper"
  if [ ! -f "$file" ]; then bad "缺 helper：$helper"; continue; fi
  if bash -n "$file"; then good "$helper 语法通过"; else bad "$helper 语法不过"; fi
  if head -8 "$file" | grep -q '^set -euo pipefail$'; then good "$helper 有 set -euo pipefail"; else bad "$helper 少了 set -euo pipefail"; fi
  if grep -q 'BASH_SOURCE' "$file"; then good "$helper 的校验函数可以被测试单独 source"; else bad "$helper 没做可测试的入口拆分"; fi
  if grep -Eq '(^|[^a-zA-Z])eval|\bxargs\b' "$file"; then bad "$helper 里出现了 eval/xargs"; else good "$helper 没有 eval/xargs"; fi
done

source "$HELPERS/qingsu-backup"
source "$HELPERS/qingsu-set-gate"
source "$HELPERS/qingsu-container-health"
# helper 自带的 set -e 只在它自己被直接执行时才有意义；测试里必须关掉才喂得出反样本
set +e

if valid_backup_arguments; then good "backup 接受无参数调用"; else bad "backup 的无参数调用被拒"; fi
for wrong in '--help' ';rm -rf /' '/etc/passwd' 'qingsu-console'; do
  if valid_backup_arguments "$wrong"; then bad "backup 接受了参数：[$wrong]"; else good "backup 拒绝参数：[$wrong]"; fi
done

for ok in 0 7 42 62 16384 999999; do
  if valid_gate_arguments "$ok"; then good "门值合法：$ok"; else bad "合法门值被拒：[$ok]"; fi
done
for wrong in '42;rm -rf /' '../../etc/passwd' '/opt/qingsu/data/min_build' '1234567' '' ' 42' '42 ' '-1' '0x10' '$(id)' '`id`' '42 42'; do
  if valid_gate_arguments "$wrong"; then bad "非法门值被接受：[$wrong]"; else good "非法门值被拒：[$wrong]"; fi
done
if valid_gate_arguments 42 /etc/passwd; then bad "set-gate 能接受第二个路径参数"; else good "set-gate 只收一个参数，路径进不来"; fi

for ok in qingsu-console qingsu-tls; do
  if valid_container_arguments "$ok"; then good "容器名在白名单：$ok"; else bad "白名单容器名被拒：[$ok]"; fi
done
for wrong in 'qingsu-console;rm -rf /' 'qingsu-console-x' 'console' '../../etc/passwd' 'docker' '' '-lc' 'qingsu-tls qingsu-console'; do
  if valid_container_arguments "$wrong"; then bad "非法容器名被接受：[$wrong]"; else good "非法容器名被拒：[$wrong]"; fi
done

# 落点必须是写死的常量，且确实走"同目录临时文件 + mv 原子替换"
grep -q '^GATE_FILE=/opt/qingsu/data/min_build$' "$HELPERS/qingsu-set-gate" \
  && good "门文件路径是常量，不来自参数" || bad "门文件路径不是写死的常量"
grep -q 'cat > "$tmp"' "$HELPERS/qingsu-set-gate" && grep -q 'mv -f "$tmp" "$GATE_FILE"' "$HELPERS/qingsu-set-gate" \
  && good "写门是同目录临时文件 + mv 原子替换" || bad "写门没有走 cat > 临时文件 + mv 的原子替换"
grep -q 'exec docker inspect --format' "$HELPERS/qingsu-container-health" \
  && good "健康查询只有固定 docker inspect --format 一条" || bad "健康查询不止一条固定命令"
grep -Fq 'exec /usr/bin/systemd-run --quiet --wait --pipe --collect --property=RuntimeMaxSec=590 "$PYTHON_BIN" "$BACKUP_SCRIPT"' "$HELPERS/qingsu-backup" \
  && good "backup 是固定脚本、固定解释器" || bad "backup 的命令形状不固定"

WRITE_DIR=$(mktemp -d 2>/dev/null || echo "${TEMP:-/tmp}/qingsu-gate-$$")
mkdir -p "$WRITE_DIR"
GATE_FILE="$WRITE_DIR/min_build"
if write_gate_value 62; then
  if [ "$(cat "$GATE_FILE" 2>/dev/null)" = "62" ]; then good "write_gate_value 落盘内容正确"; else bad "write_gate_value 落盘内容不对：[$(cat "$GATE_FILE")]"; fi
  LEFT=$(find "$WRITE_DIR" -name '.min_build.*' -print)
  [ -z "$LEFT" ] && good "原子替换没留下临时文件" || bad "残留临时文件：$LEFT"
else
  bad "write_gate_value 正常写入失败"
fi
ln -sf /etc/passwd "$WRITE_DIR/symlinked" 2>/dev/null
GATE_FILE="$WRITE_DIR/symlinked"
if [ ! -L "$GATE_FILE" ]; then
  printf '   提示 本机建不出真符号链接（Git Bash 拿副本代替），"门文件是符号链接就拒写"只能在 Linux 上判\n'
elif write_gate_value 42 2>/dev/null; then
  bad "门文件是符号链接时仍然写了（可以指到 /etc/passwd）"
else
  good "门文件是符号链接时拒绝写入"
fi
rm -rf "$WRITE_DIR"

for argv in '../../etc/passwd' '4;rm -rf /'; do
  if bash "$HELPERS/qingsu-set-gate" "$argv" >/dev/null 2>&1; then bad "整脚本执行没挡住：[$argv]"; else good "整脚本执行挡住并退了非零：[$argv]"; fi
done
if bash "$HELPERS/qingsu-backup" nowait >/dev/null 2>&1; then bad "整脚本执行没挡住带参数的 backup"; else good "整脚本执行挡住带参数的 backup"; fi
if bash "$HELPERS/qingsu-container-health" 'qingsu-console;rm -rf /' >/dev/null 2>&1; then bad "整脚本执行没挡住注入的容器名"; else good "整脚本执行挡住注入的容器名"; fi

if [ -f "$HERE/qingsu-ops-sudoers" ]; then
  # 只看真正的规则行，注释里那句"不给 docker 组/不给 ALL"不算授权
  SUDO_RULES=$(grep -v '^[[:space:]]*#' "$HERE/qingsu-ops-sudoers")
  if printf '%s' "$SUDO_RULES" | grep -q 'NOPASSWD'; then good "sudoers 用 NOPASSWD 且只给三个 helper 绝对路径"; else bad "sudoers 缺 NOPASSWD 配置"; fi
  if printf '%s' "$SUDO_RULES" | grep -Eq 'NOPASSWD: *ALL|ALL=\(ALL\)[[:space:]]+[A-Z]*[[:space:]]*:/[A-Za-z*]+ +ALL'; then bad "sudoers 给了 ALL 通配"; else good "sudoers 没有 ALL 通配"; fi
  if printf '%s' "$SUDO_RULES" | grep -q 'docker'; then bad "sudoers 规则里出现了 docker"; else good "sudoers 规则不含 docker 授权"; fi
  MISSING=""
  for helper in qingsu-backup qingsu-set-gate qingsu-container-health; do
    printf '%s' "$SUDO_RULES" | grep -q "/usr/local/sbin/$helper" || MISSING="$MISSING $helper"
  done
  [ -z "$MISSING" ] && good "三个 helper 都在 sudoers 里" || bad "sudoers 缺：$MISSING"
else
  bad "缺 deploy/qingsu-ops-sudoers"
fi

UNIT="$HERE/qingsu-ops.service"
grep -q '^User=qingsu-ops$' "$UNIT" && good "unit 已经是 User=qingsu-ops" || bad "unit 还在用 root 或没设服务账号"
! grep -q '^User=root$' "$UNIT" && good "unit 里没有 root 身份" || bad "unit 里还留着 User=root"
grep -q '^UMask=0002$' "$UNIT" && good "unit 保留 UMask=0002" || bad "UMask=0002 被删了（-wal 归属会坏）"
for key in ProtectSystem=strict PrivateTmp=yes ReadWritePaths=; do
  grep -q "^$key" "$UNIT" && good "unit 有 $key" || bad "unit 缺 $key"
done

printf '绿 %s 项\n' "$GOODS"
if [ "$FAIL" = "0" ]; then echo "HELPERS_OK"; else echo "HELPERS_HAS_FAILURES"; fi
exit "$FAIL"
