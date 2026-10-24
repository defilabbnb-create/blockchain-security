#!/bin/sh
# Cloudflare Tunnel 启动包装器
#
# 为什么不能直接跑 cloudflared：
#   本机 Shadowrocket 开着 fake-ip。系统 DNS 把 region*.v2.argotunnel.com 解析到
#   198.18.x.x 假 IP，结果是：
#     - QUIC(UDP 7844) 超时（fake-ip 路径上 UDP 7844 不通）
#     - http2(TCP 7844) 在 TLS 握手阶段被截断（TLS handshake with edge error: EOF）
#   即使用 1.1.1.1 直解拿到真实边缘 IP，只要出站连接仍走 Shadowrocket 的 TUN，
#   握手照样失败。
#
# 实测唯一可行的组合（三个条件缺一不可）：
#   1) 用 1.1.1.1 直解拿到 Cloudflare 边缘真实 IP
#      （UDP 53 直连 1.1.1.1 未被劫持，dig @1.1.1.1 返回真实 IP）
#   2) --edge-bind-address 绑定物理网卡地址，让出站连接绕开 Shadowrocket 的 TUN
#   3) protocol: http2（QUIC 的 UDP 7844 在本机不通）
#   只做 1) -> TLS EOF；只做 2) -> 连到假 IP 超时；1)+2)+3) -> 注册成功。
#
# Cloudflare 边缘 IP 会轮换，所以定期重解析并重启 cloudflared。
#
# 实测注册成功的边缘节点：lax01 / lax09 / lax10 / lax11。

set -u

CF_BIN="/opt/homebrew/bin/cloudflared"
# 配置放在 ~/Library/Application Support/ 下，不是仓库里：
# macOS TCC 禁止 launchd 拉起的进程读 Desktop 下的文件，cloudflared 会卡在
# open() 打开配置那一步（进程活着但从不联网，公网访问报 error 1033）。
# 仓库里的 deploy/tunnel/cloudflared/ 是真源，用 deploy.sh 同步过来。
CONFIG="${TUNNEL_CF_CONFIG:-$HOME/Library/Application Support/SecurityWebTunnel/cloudflared/config.yml}"
LOG="$HOME/Library/Logs/SecurityWebTunnel/cloudflared.log"
RESOLVER="1.1.1.1"
REFRESH_SECONDS=21600

if [ ! -r "$CONFIG" ]; then
  echo "找不到可读的 cloudflared 配置: $CONFIG" >&2
  echo "先执行: sh deploy/tunnel/cloudflared/deploy.sh" >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >>"$LOG"
}

# 物理网卡 IPv4：排除 198.18.0.0/15（fake-ip 段）。
# 优先取与物理默认网关同网段的地址，其次取任一 en* 网卡的地址。
detect_bind_ip() {
  GATEWAY=$(netstat -rn -f inet 2>/dev/null \
    | awk '$1 == "default" && $NF !~ /^utun/ { print $2; exit }')
  CAND=""
  # 注意：ifconfig -l 输出是空格分隔的单行，必须先转成每行一个接口名。
  for DEV in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^en'); do
    IP=$(ipconfig getifaddr "$DEV" 2>/dev/null) || continue
    [ -z "$IP" ] && continue
    case "$IP" in
      198.18.*|198.19.*) continue ;;
    esac
    if [ -n "$GATEWAY" ]; then
      GWNET=$(echo "$GATEWAY" | awk -F. '{ print $1"."$2"."$3 }')
      IPNET=$(echo "$IP" | awk -F. '{ print $1"."$2"."$3 }')
      if [ "$GWNET" = "$IPNET" ]; then
        echo "$IP"
        return 0
      fi
    fi
    if [ -z "$CAND" ]; then
      CAND="$IP"
    fi
  done
  if [ -n "$CAND" ]; then
    echo "$CAND"
  fi
  return 0
}

# 从 1.1.1.1 直解 Cloudflare 边缘地址，逗号分隔的 host:port 列表。
resolve_edges() {
  OUT=""
  for HOST in region1.v2.argotunnel.com region2.v2.argotunnel.com; do
    IPS=$(dig +short +time=3 +tries=2 @"$RESOLVER" "$HOST" A 2>/dev/null \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -2)
    for ONE in $IPS; do
      case "$ONE" in
        198.18.*|198.19.*) continue ;;
      esac
      if [ -n "$OUT" ]; then
        OUT="$OUT,"
      fi
      OUT="$OUT$ONE:7844"
    done
  done
  echo "$OUT"
}

while :; do
  BIND=$(detect_bind_ip)
  EDGES=$(resolve_edges)
  if [ -z "$EDGES" ] || [ -z "$BIND" ]; then
    log "解析失败 bind='$BIND' edges='$EDGES'，30 秒后重试"
    sleep 30
    continue
  fi

  log "启动 cloudflared bind=$BIND edges=$EDGES"
  TUNNEL_EDGE="$EDGES" "$CF_BIN" tunnel --config "$CONFIG" \
    --edge-bind-address "$BIND" run >>"$LOG" 2>&1 &
  CF_PID=$!

  # 定期刷新边缘 IP：Cloudflare 会轮换边缘地址，旧的地址可能失效。
  (
    sleep "$REFRESH_SECONDS"
    kill -TERM "$CF_PID" 2>/dev/null
  ) &
  REFRESH_PID=$!

  wait "$CF_PID"
  kill "$REFRESH_PID" 2>/dev/null || true
  log "cloudflared 退出，5 秒后重启"
  sleep 5
done
