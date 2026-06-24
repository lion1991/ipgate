#!/usr/bin/env bash
#
# ipgate-agent 安装脚本（需 root）。
#
#   sudo ./install.sh [--binary <path>] [--yes]
#
# 默认从脚本同目录找 ipgate-agent / ipgate-agent-<arch> 二进制。
# --yes 跳过所有交互确认（无人值守）。
#
set -euo pipefail

PREFIX=/usr/local/bin
CONF_DIR=/etc/ipgate
DATA_DIR=/var/lib/ipgate
UNIT_DST=/etc/systemd/system/ipgate-agent.service
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC=""
ASSUME_YES=0

log()  { printf '\033[1;32m[ipgate]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ipgate] 警告:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ipgate] 错误:\033[0m %s\n' "$*" >&2; exit 1; }

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  read -r -p "$1 [y/N] " ans
  [ "$ans" = y ] || [ "$ans" = Y ]
}

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BIN_SRC="$2"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    *) die "未知参数: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "请用 root 运行（sudo）。"

# --- 定位二进制 ---
if [ -z "$BIN_SRC" ]; then
  arch="$(uname -m)"
  for cand in "$SCRIPT_DIR/ipgate-agent" "$SCRIPT_DIR/ipgate-agent-$arch" \
              "$SCRIPT_DIR/ipgate-agent-x86_64-unknown-linux-musl" \
              "$SCRIPT_DIR/ipgate-agent-aarch64-unknown-linux-musl"; do
    [ -f "$cand" ] && { BIN_SRC="$cand"; break; }
  done
fi
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || die "找不到 ipgate-agent 二进制，用 --binary 指定。"

# --- 前置检查 ---
command -v nft >/dev/null 2>&1 || die "未找到 nft。请先安装 nftables。"

# 与现有防火墙共存警告（ADR 0002：default-drop 应独占，drop 裁决终局）。
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
  warn "检测到 ufw 处于启用状态，会与 ipgate 的 default-drop 冲突。建议: ufw disable"
  confirm "仍要继续安装吗?" || die "已取消。"
fi
if systemctl is-active --quiet firewalld 2>/dev/null; then
  warn "检测到 firewalld 处于启用状态，会与 ipgate 的 default-drop 冲突。建议: systemctl disable --now firewalld"
  confirm "仍要继续安装吗?" || die "已取消。"
fi

# --- 安装文件 ---
log "安装二进制 -> $PREFIX/ipgate-agent"
install -m 0755 "$BIN_SRC" "$PREFIX/ipgate-agent"

mkdir -p "$CONF_DIR"
if [ ! -f "$CONF_DIR/config.json" ]; then
  install -m 0644 "$SCRIPT_DIR/config.example.json" "$CONF_DIR/config.json"
  log "写入默认配置 $CONF_DIR/config.json"
else
  log "保留已有配置 $CONF_DIR/config.json"
fi

mkdir -p "$DATA_DIR"
chmod 0700 "$DATA_DIR"

# --- 防自锁：把当前 SSH 来源 IP 加入放行名单 ---
# default-drop 一旦生效，除管理端口/established/名单/公开端口外一律拒，含 SSH！
if [ -n "${SSH_CONNECTION:-}" ]; then
  admin_ip="$(awk '{print $1}' <<<"$SSH_CONNECTION")"
  case "$admin_ip" in
    *:*) cidr="$admin_ip/128" ;;
    *)   cidr="$admin_ip/32"  ;;
  esac
  warn "default-drop 启用后仅放行名单内的源 IP 可访问（含 SSH）。"
  warn "你正从 $admin_ip 经 SSH 连接——将把它加入放行名单以防自锁。"
  "$PREFIX/ipgate-agent" --config "$CONF_DIR/config.json" allow "$cidr" --note "installer: SSH client" \
    && log "已放行 $cidr"
else
  warn "未检测到 SSH 连接（本地控制台?）。启动后只有管理端口 19186 可达；"
  warn "如需保留其它入站访问，先用: ipgate-agent allow <你的IP>/32"
  confirm "了解风险并继续?" || die "已取消。"
fi

# --- 安装 systemd unit ---
log "安装 systemd unit"
install -m 0644 "$SCRIPT_DIR/ipgate-agent.service" "$UNIT_DST"
systemctl daemon-reload
systemctl enable --now ipgate-agent.service

sleep 1
if systemctl is-active --quiet ipgate-agent.service; then
  log "服务已启动。"
else
  warn "服务未处于 active，请查看: journalctl -u ipgate-agent -e"
fi

echo
log "生成首个配对码（供客户端入网）:"
"$PREFIX/ipgate-agent" --config "$CONF_DIR/config.json" pair || true
echo
log "完成。校验 ruleset: nft list table inet ipgate"
