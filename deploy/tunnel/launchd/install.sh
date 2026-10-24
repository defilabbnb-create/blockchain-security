#!/bin/sh
# 区块链安全 Web 隧道 —— launchd 任务安装
#
# 用法：sh deploy/tunnel/launchd/install.sh
#
# 为什么需要这一步：
#   隧道由四个 launchd 任务托管，任何一个被重载或机器重启后都要能自动恢复：
#     - proxy            : 自建代理（8789），做 Host/Origin 改写、口令校验、gzip
#     - cloudflared      : Cloudflare Tunnel 主隧道（blksec.luckytad.vip）
#     - serveo           : serveo.net 兜底隧道
#     - serveo-watchdog  : 兜底隧道看门狗（每 120 秒探测一次）
#
#   plist 源文件在 deploy/tunnel/launchd/，本脚本把它们安装到
#   ~/Library/LaunchAgents/ 并 bootstrap 到 gui/<uid> 域。
#
# 注意：plist 里的路径是本机绝对路径（/Users/<用户名>/...）。
#   换机器时需要改这几处：
#     - proxy plist：proxy-server.mjs 与 .plainpass 的路径
#     - cloudflared plist：run-cloudflared.sh 的路径（由 cloudflared/deploy.sh 部署）
#   本脚本会用当前用户目录自动改写这两处。
#
# 幂等：重复执行只会重新加载已安装的任务，不会产生重复项。

set -eu

# 脚本位于 deploy/tunnel/launchd/，仓库根目录要往上三层。
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$ROOT/deploy/tunnel/launchd"
DEST="$HOME/Library/LaunchAgents"
DOMAIN="gui/$(id -u)"

# plist 模板里写死了原机器的仓库绝对路径。换机器时把这段前缀换成本机的。
OLD_ROOT="/Users/d288/Desktop/区块链安全"

if [ ! -d "$SRC" ]; then
  echo "找不到 plist 源目录: $SRC" >&2
  exit 1
fi

mkdir -p "$DEST"

# 凭据文件必须先存在，否则代理会启动失败（要口令模式下找不到口令文件会明确退出）。
if [ ! -f "$ROOT/deploy/tunnel/.plainpass" ]; then
  echo "缺少口令文件: $ROOT/deploy/tunnel/.plainpass" >&2
  echo "从模板创建并填入口令：cp deploy/tunnel/.plainpass.example deploy/tunnel/.plainpass" >&2
  exit 1
fi

for plist in "$SRC"/*.plist; do
  [ -e "$plist" ] || continue
  name=$(basename "$plist")
  target="$DEST/$name"

  # 把模板里的仓库绝对路径改写成本机当前路径（换机器后不用手改 plist）。
  sed "s#$OLD_ROOT#$ROOT#g" "$plist" >"$target"
  chmod 644 "$target"

  # 已加载过先 bootout，避免 bootstrap 报「已存在」。
  launchctl bootout "$DOMAIN/${name%.plist}" 2>/dev/null || true
  # 旧进程释放监听端口需要一点时间。bootout 后立刻 bootstrap 会因
  # 「端口已被占用」失败（实测 proxy 任务就是这样挂掉的），这里轮询等待。
  if ! launchctl bootstrap "$DOMAIN" "$target" 2>/dev/null; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      sleep 1
      if launchctl bootstrap "$DOMAIN" "$target" 2>/dev/null; then break; fi
    done
  fi
  if launchctl print "$DOMAIN/${name%.plist}" >/dev/null 2>&1; then
    echo "已安装并启动: $name"
  else
    echo "安装失败（先看日志）: $name" >&2
    exit 1
  fi
done

echo
echo "当前隧道任务："
launchctl list | grep security.webtunnel || echo "  未注册"
echo
echo "查看状态：sh deploy/tunnel/status.sh"
