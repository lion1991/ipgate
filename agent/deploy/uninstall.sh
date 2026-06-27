#!/usr/bin/env bash
#
# ipgate-agent 卸载脚本（需 root）。
#
#   sudo ./uninstall.sh [--yes] [--purge]
#
# --purge 删除配置与数据（证书/密钥/名单）。--yes 跳过确认。
#
set -euo pipefail

PREFIX=/usr/local/bin
CONF_DIR=/etc/ipgate
DATA_DIR=/var/lib/ipgate
UNIT_DST=/etc/systemd/system/ipgate-agent.service
ASSUME_YES=0
PURGE=0

log()  { printf '\033[1;32m[ipgate]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ipgate] 警告:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ipgate] 错误:\033[0m %s\n' "$*" >&2; exit 1; }
confirm() { [ "$ASSUME_YES" = 1 ] && return 0; read -r -p "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]; }

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1; shift ;;
    --purge)  PURGE=1; shift ;;
    *) die "未知参数: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "请用 root 运行（sudo）。"

log "停止并禁用服务"
systemctl disable --now ipgate-agent.service 2>/dev/null || true
rm -f "$UNIT_DST"
systemctl daemon-reload 2>/dev/null || true

warn "接下来将 flush 掉 inet ipgate 表——这会**拆除防火墙**，主机回到无 ipgate 规则的状态。"
if confirm "执行 flush?"; then
  if [ -x "$PREFIX/ipgate-agent" ]; then
    "$PREFIX/ipgate-agent" uninstall || nft delete table inet ipgate 2>/dev/null || true
  else
    nft delete table inet ipgate 2>/dev/null || true
  fi
  log "已 flush。"
fi

rm -f "$PREFIX/ipgate-agent"
log "已删除二进制。"

# 移除安装时写入的「仅转发」SSH 隧道公钥（标记 ipgate-tunnel，ADR 0007）。趁 config 还在先读 ssh_user。
suser="$(grep -o '"ssh_user"[^,]*' "$CONF_DIR/config.json" 2>/dev/null | sed 's/.*: *"//; s/".*//')"
suser="${suser:-root}"
home="$(getent passwd "$suser" 2>/dev/null | cut -d: -f6)"; [ -n "$home" ] || home="/root"
akf="$home/.ssh/authorized_keys"
if [ -f "$akf" ] && grep -qF "ipgate-tunnel" "$akf" 2>/dev/null; then
  grep -vF "ipgate-tunnel" "$akf" > "$akf.tmp" && mv "$akf.tmp" "$akf" && chmod 600 "$akf"
  log "已从 $suser 的 authorized_keys 移除仅转发隧道公钥。"
fi

if [ "$PURGE" = 1 ] || confirm "删除配置与数据（$CONF_DIR, $DATA_DIR：含密钥/名单）?"; then
  rm -rf "$CONF_DIR" "$DATA_DIR"
  log "已删除配置与数据。"
else
  log "保留 $CONF_DIR 与 $DATA_DIR。"
fi

log "卸载完成。"
