#!/bin/sh
# 区块链安全 Web 隧道 —— 状态查看
#
# 用法：sh deploy/tunnel/status.sh
#
# 说明：
#   - 主隧道是 Cloudflare Tunnel，域名固定：blksec.luckytad.vip
#     （子域名，不用 www；域名字符串在各 DNS 记录里固定，不随会话漂移）。
#   - serveo.net 的免费隧道是兜底，域名在每次隧道会话重建时都会变（随机子域名）。
#   - 隧道三层结构：
#       公网 -> Cloudflare 边缘 / serveo(SSH 反向转发)
#             -> 127.0.0.1:8789(自建代理) -> 127.0.0.1:8788(Web 服务)
#     中间那层代理负责：改写 Host/Origin（应用只允许本机访问）、校验口令、
#     把 chunked 响应转成 Content-Length（隧道不支持 chunked，会丢响应体）。
#
# 兜底地址的取值方式（这里改过，原因见下）：
#   旧写法是 `grep -oE 'https://[a-z0-9.-]+serveousercontent.com' | tail -1`，
#   直接从 serveo 日志里取最后一个域名。但 serveo 会单方面回收转发，而
#   **ssh 进程仍然活着**，所以日志里的域名会在「转发已死」之后继续存在。
#   旧写法会把这种失效域名照样显示成「兜底地址」，公网访问实际是 502 ——
#   状态看着正常，语义是错的。
#   现在改为读看门狗写下的状态文件（scripts/tunnel_serveo_watchdog.py）：
#   只有「探测通过」且「结论未过期」的域名才会作为可用兜底地址展示；
#   其余情况显式标注不可用并给出原因，失效域名只作为诊断信息出现。
set -e
ROOT="/Users/d288/Desktop/区块链安全"
CF_LOG="$HOME/Library/Logs/SecurityWebTunnel/cloudflared.log"
SERVE_LOG="$HOME/Library/Logs/SecurityWebTunnel/serveo.log"
SERVE_STATE="$HOME/Library/Application Support/SecurityWebTunnel/serveo-state.json"
CF_HOST="blksec.luckytad.vip"
CF_URL="https://${CF_HOST}"

PASS=$(cat "$ROOT/deploy/tunnel/.plainpass")

# 兜底地址：优先用看门狗的已验证结论。
# 看门狗没跑过（状态文件不存在）时退回日志取域名，但会明确标注「未验证」。
# 用 `json` 子命令读机器可读输出，不去解析人类可读文本里的固定措辞。
SERVE_URL=""
SERVE_NOTE=""
if [ -f "$SERVE_STATE" ]; then
  SERVE_JSON=$(python3 "$ROOT/scripts/tunnel_serveo_watchdog.py" json 2>/dev/null || true)
  if [ -n "$SERVE_JSON" ]; then
    SERVE_URL=$(printf '%s' "$SERVE_JSON" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("url") or "")' 2>/dev/null || true)
    SERVE_VERDICT=$(printf '%s' "$SERVE_JSON" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("verdict") or "")' 2>/dev/null || true)
    SERVE_REASON=$(printf '%s' "$SERVE_JSON" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("reason") or "")' 2>/dev/null || true)
    if [ -z "$SERVE_URL" ]; then
      SERVE_NOTE="（看门狗判定不可用：${SERVE_VERDICT:-未知} / ${SERVE_REASON:-无原因说明}）"
    fi
  fi
fi
if [ -z "$SERVE_URL" ] && [ -z "$SERVE_NOTE" ]; then
  # 看门狗没跑过：从日志取域名仅作诊断，并标成未验证。
  SERVE_URL=$(grep -oE "https://[a-z0-9.-]+serveousercontent\.com" "$SERVE_LOG" 2>/dev/null | tail -1 || true)
  SERVE_NOTE="（未验证：看门狗尚未运行，此域名来自日志，可能已失效）"
fi

echo "主隧道地址 : ${CF_URL}"
if [ -n "$SERVE_NOTE" ]; then
  echo "兜底地址   : <不可用>"
  echo "             ${SERVE_NOTE}"
  if [ -n "$SERVE_URL" ]; then
    echo "             失效域名  : ${SERVE_URL}"
  fi
else
  echo "兜底地址   : ${SERVE_URL:-<serveo 隧道尚未分配域名>}"
fi

# 访问方式：探测实际行为，不读配置猜。
# 本地代理对无认证请求返回 200 => 免口令；返回 401 => 需要口令。
AUTH_MODE=$(curl -s -m 8 -o /dev/null -w "%{http_code}" http://127.0.0.1:8789/api/health || echo "000")
case "$AUTH_MODE" in
  200)
    echo "访问方式   : 免口令 —— 浏览器直接打开上面地址即可"
    echo "             （公网公开访问：任何能访问该地址的人都可调用本机 /api 路由）"
    ;;
  401)
    echo "访问口令   : ${PASS}"
    echo "访问方式   : 用户名 sec，密码见上；浏览器输入后弹窗认证"
    ;;
  *)
    echo "访问方式   : <无法判定>（本地代理探测返回 ${AUTH_MODE}）"
    ;;
esac
echo
echo "--- 进程（launchd 托管）---"
launchctl list | grep security.webtunnel || echo "未注册"
echo
echo "--- Cloudflare 边缘连接（多连接并行）---"
if [ -f "$CF_LOG" ]; then
  grep -E "Registered tunnel connection" "$CF_LOG" | tail -6 \
    | sed -E 's/.*connIndex=([0-9]+).*ip=([0-9.]+).*location=([a-z0-9]+).*protocol=([a-z0-9]+).*/  connIndex=\1 ip=\2 location=\3 protocol=\4/'
  echo "  已注册连接数: $(grep -cE 'Registered tunnel connection' "$CF_LOG")"
fi
echo
echo "--- 本地健康检查（应返回 200）---"
if [ "$AUTH_MODE" = "200" ]; then
  curl -s -m 8 -o /dev/null -w "http://127.0.0.1:8789/api/health -> %{http_code}\n" \
    http://127.0.0.1:8789/api/health
else
  curl -s -m 8 -u "sec:${PASS}" -o /dev/null -w "http://127.0.0.1:8789/api/health -> %{http_code}\n" \
    http://127.0.0.1:8789/api/health
fi
echo
echo "--- 公网健康检查（Cloudflare 隧道，应返回 200）---"
if [ "$AUTH_MODE" = "200" ]; then
  curl -s -m 30 -o /dev/null -w "${CF_URL}/api/health -> %{http_code}\n" \
    "${CF_URL}/api/health"
else
  curl -s -m 30 -u "sec:${PASS}" -o /dev/null -w "${CF_URL}/api/health -> %{http_code}\n" \
    "${CF_URL}/api/health"
fi
if [ -n "$SERVE_URL" ] && [ -z "$SERVE_NOTE" ]; then
  if [ "$AUTH_MODE" = "200" ]; then
    curl -s -m 25 -o /dev/null -w "${SERVE_URL}/api/health -> %{http_code}\n" "${SERVE_URL}/api/health"
  else
    curl -s -m 25 -u "sec:${PASS}" -o /dev/null -w "${SERVE_URL}/api/health -> %{http_code}\n" "${SERVE_URL}/api/health"
  fi
fi
echo
echo "--- serveo 看门狗状态（serveo 为兜底，主隧道挂了才用）---"
if [ -f "$SERVE_STATE" ]; then
  python3 "$ROOT/scripts/tunnel_serveo_watchdog.py" status 2>/dev/null || echo "看门狗状态读取失败"
else
  echo "看门狗尚未运行（状态文件不存在）：sh deploy/tunnel/cloudflared/deploy.sh 之后执行 scripts/tunnel_serveo_watchdog.py install"
fi
