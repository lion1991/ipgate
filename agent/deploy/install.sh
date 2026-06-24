#!/usr/bin/env bash
#
# ipgate-agent 安装脚本（需 root）。
#
# 自动从 GitHub Releases 下载最新 agent 并安装；也可离线指定本地二进制。
#
#   # 一键（仓库已 public）：
#   curl -fsSL https://raw.githubusercontent.com/lion1991/ipgate/main/agent/deploy/install.sh | sudo bash
#
#   # 或下载后运行：
#   sudo ./install.sh [--version vX.Y.Z] [--repo owner/name] [--binary <path>] [--yes]
#
#   --version   指定版本（默认 latest）
#   --repo      指定仓库（默认 lion1991/ipgate，或 $IPGATE_REPO）
#   --binary    用本地二进制，跳过下载（离线/整包安装）
#   --yes / -y  跳过所有交互确认（无人值守）
#
set -euo pipefail

PREFIX=/usr/local/bin
CONF_DIR=/etc/ipgate
DATA_DIR=/var/lib/ipgate
UNIT_DST=/etc/systemd/system/ipgate-agent.service
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /tmp)"
REPO="${IPGATE_REPO:-lion1991/ipgate}"
VERSION="${IPGATE_VERSION:-latest}"
BIN_SRC=""
TMP_BIN=""
ASSUME_YES=0

log()  { printf '\033[1;32m[ipgate]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ipgate] 警告:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ipgate] 错误:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() { [ -n "$TMP_BIN" ] && rm -f "$TMP_BIN" 2>/dev/null || true; }
trap cleanup EXIT

# 交互确认：优先读 /dev/tty，使 `curl | bash` 下仍能提问。
confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  local ans=""
  if [ -r /dev/tty ]; then
    read -r -p "$1 [y/N] " ans </dev/tty
  else
    read -r -p "$1 [y/N] " ans
  fi
  [ "$ans" = y ] || [ "$ans" = Y ]
}

fetch() { # <url> <dst>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    return 1
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else echo ""; fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --binary)  BIN_SRC="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --repo)    REPO="$2"; shift 2 ;;
    --yes|-y)  ASSUME_YES=1; shift ;;
    *) die "未知参数: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "请用 root 运行（sudo）。"

# --- 架构 → release 资产名 ---
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  ASSET="ipgate-agent-x86_64-unknown-linux-musl" ;;
  aarch64|arm64) ASSET="ipgate-agent-aarch64-unknown-linux-musl" ;;
  *)             ASSET="" ;;
esac

# --- 从 Releases 下载并校验 ---
download_binary() {
  [ -n "$ASSET" ] || die "暂不支持的架构: $arch（目前发布 x86_64）。可用 --binary 指定本地二进制。"
  local base
  if [ "$VERSION" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION"
  fi
  TMP_BIN="$(mktemp)"
  log "下载 $ASSET（$VERSION）<- $REPO"
  fetch "$base/$ASSET" "$TMP_BIN" \
    || die "下载失败。检查：仓库是否 public、版本 $VERSION 是否存在、网络是否可达 github.com。"
  [ -s "$TMP_BIN" ] || die "下载到空文件。"

  # SHA256 校验（尽力而为）。
  local sums want got
  sums="$(mktemp)"
  if fetch "$base/SHA256SUMS" "$sums" 2>/dev/null && [ -s "$sums" ]; then
    want="$(grep " ${ASSET}\$" "$sums" | awk '{print $1}' | head -n1)"
    got="$(sha256_of "$TMP_BIN")"
    if [ -n "$want" ] && [ -n "$got" ]; then
      [ "$want" = "$got" ] && log "SHA256 校验通过" || { rm -f "$sums"; die "SHA256 不匹配！want=$want got=$got"; }
    else
      warn "无法比对 SHA256（缺校验值或本机无 sha256sum/shasum），跳过。"
    fi
  else
    warn "未取到 SHA256SUMS，跳过校验。"
  fi
  rm -f "$sums"
  chmod +x "$TMP_BIN"
  BIN_SRC="$TMP_BIN"
}

# --- 定位二进制：--binary > 脚本同目录 > 下载 ---
if [ -z "$BIN_SRC" ]; then
  for cand in "$SCRIPT_DIR/ipgate-agent" "$SCRIPT_DIR/$ASSET" \
              "$SCRIPT_DIR/ipgate-agent-x86_64-unknown-linux-musl" \
              "$SCRIPT_DIR/ipgate-agent-aarch64-unknown-linux-musl"; do
    [ -f "$cand" ] && { BIN_SRC="$cand"; log "使用同目录二进制 $cand"; break; }
  done
fi
[ -z "$BIN_SRC" ] && download_binary
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || die "找不到也下载不到 ipgate-agent 二进制。"

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
if [ -f "$CONF_DIR/config.json" ]; then
  log "保留已有配置 $CONF_DIR/config.json"
elif [ -f "$SCRIPT_DIR/config.example.json" ]; then
  install -m 0644 "$SCRIPT_DIR/config.example.json" "$CONF_DIR/config.json"
  log "写入默认配置 $CONF_DIR/config.json"
else
  # 同目录没有模板（如 curl|bash 或只下了二进制）→ 内置默认，保持自包含。
  cat > "$CONF_DIR/config.json" <<'JSON'
{
  "bind": "0.0.0.0:19186",
  "mgmt_port": 19186,
  "public_tcp": [],
  "public_udp": [],
  "data_dir": "/var/lib/ipgate"
}
JSON
  chmod 0644 "$CONF_DIR/config.json"
  log "未找到 config.example.json，已写入内置默认配置 $CONF_DIR/config.json"
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
  warn "若这台机器对外提供 Web 等服务，务必先把 80/443 等端口写进 config.json 的 public_tcp！"
  confirm "了解风险并继续?" || die "已取消。"
fi

# --- 安装 systemd unit ---
log "安装 systemd unit"
if [ -f "$SCRIPT_DIR/ipgate-agent.service" ]; then
  install -m 0644 "$SCRIPT_DIR/ipgate-agent.service" "$UNIT_DST"
else
  # 同目录没有 unit 文件 → 内置一份，保持自包含。
  cat > "$UNIT_DST" <<'UNIT'
[Unit]
Description=ipgate agent — nftables 放行名单管理（default-drop）
Documentation=https://github.com/lion1991/ipgate
Wants=network-pre.target
Before=network-pre.target
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ipgate-agent --config /etc/ipgate/config.json run
Restart=on-failure
RestartSec=2
TimeoutStartSec=30
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ipgate
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$UNIT_DST"
  log "未找到 ipgate-agent.service，已写入内置 unit"
fi
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
