#!/bin/sh
# Cloudflare Tunnel 部署脚本（把配置/凭据从 Desktop 拷到 launchd 可读的位置）
#
# 为什么需要这一步：
#   macOS TCC 限制 launchd 启动的进程读取 Desktop / Documents 等受保护目录。
#   实测：launchd 拉起的进程读 Desktop 下的文件会得到 "Operation not permitted"，
#   cloudflared 因此卡在 open() 打开配置文件那一步 —— 进程活着但从未联网，
#   表现为公网访问返回 Cloudflare error 1033。
#   /opt/homebrew/bin/node 之前被授权过（现有 webtunnel.proxy 任务因此能读
#   Desktop 下的 .plainpass），但 cloudflared 是新二进制，没有该授权。
#
# 做法：把 config.yml / credentials.json 复制到 ~/Library/Application Support/，
#   用 cp -X 去掉 com.apple.macl 标记（带该标记的文件 launchd 也拒绝执行）。
#   仓库里的 deploy/tunnel/cloudflared/ 仍是唯一真源，改完跑一次本脚本即可同步。
#
# 用法：sh deploy/tunnel/cloudflared/deploy.sh

set -eu

ROOT="/Users/d288/Desktop/区块链安全"
SRC="$ROOT/deploy/tunnel/cloudflared"
DEST="$HOME/Library/Application Support/SecurityWebTunnel/cloudflared"
RUNNER_SRC="$SRC/run.sh"
RUNNER_DEST="$HOME/Library/Application Support/SecurityWebTunnel/run-cloudflared.sh"

mkdir -p "$DEST"

# config.yml 里的 credentials-file 指向仓库内路径，部署时改写为部署位置。
sed "s#^credentials-file:.*#credentials-file: $DEST/credentials.json#" \
  "$SRC/config.yml" >"$DEST/config.yml"

cp -X "$SRC/credentials.json" "$DEST/credentials.json"
chmod 600 "$DEST/credentials.json"
chmod 644 "$DEST/config.yml"

cp -X "$RUNNER_SRC" "$RUNNER_DEST"
chmod 755 "$RUNNER_DEST"

echo "已部署到 $DEST"
ls -la "$DEST" "$RUNNER_DEST"
