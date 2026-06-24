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
#   sudo ./install.sh [--version vX.Y.Z] [--repo owner/name] [--binary <path>] [--allow IP] [--yes]
#
#   --version   指定版本（默认 latest）
#   --repo      指定仓库（默认 lion1991/ipgate，或 $IPGATE_REPO）
#   --binary    用本地二进制，跳过下载（离线/整包安装）
#   --allow     额外放行一个管理来源 IP（防自锁；可叠加在自动探测之上）
#   --force     即使已是目标版本也强制重新下载安装
#   --yes / -y  跳过所有交互确认（无人值守）
#
# 注：sudo 默认会清掉 SSH_CONNECTION，脚本已用扫进程环境/who 的方式找回 SSH 来源 IP；
#     若仍探测不到（如 curl|bash 无 tty），用 --allow 指定，或 `sudo -E` 保留环境。
#
set -euo pipefail

PREFIX=/usr/local/bin
CONF_DIR=/etc/ipgate
DATA_DIR=/var/lib/ipgate
UNIT_DST=/etc/systemd/system/ipgate-agent.service
# 经 curl|bash 管道运行时 $0 是 "bash"（非文件）→ SCRIPT_DIR 置空，不在 cwd 找二进制，
# 强制走下载（否则会误用 cwd 里残留的旧二进制）。下载/整包(./install.sh)两种场景都正确。
if [ -f "$0" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
else
  SCRIPT_DIR=""
fi
REPO="${IPGATE_REPO:-lion1991/ipgate}"
VERSION="${IPGATE_VERSION:-latest}"
BIN_SRC=""
TMP_BIN=""
ASSUME_YES=0
ALLOW_EXTRA=""
FORCE=0

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

# 解析 latest 实际指向的 tag（走 releases/latest 的重定向，不耗 API 配额）。失败返回空。
resolve_latest_tag() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSLI -o /dev/null -w '%{url_effective}\n' \
      "https://github.com/$REPO/releases/latest" 2>/dev/null | sed -n 's#.*/releases/tag/##p'
  else
    wget -q -S -O /dev/null "https://github.com/$REPO/releases/latest" 2>&1 \
      | sed -n 's#.*[Ll]ocation:.*/releases/tag/##p' | tail -n1
  fi
}

# 收集需放行的管理来源 IP（防自锁）。sudo 会清掉 SSH_CONNECTION/SSH_CLIENT，
# 故 root 时再扫进程环境找回；叠加 who 与 --allow。去重、剔除空与本地显示 :0。
collect_admin_ips() {
  # 在命令替换的子shell里跑：关掉 errexit/pipefail，容忍 /proc 进程退出竞态、grep 无匹配。
  set +e +o pipefail
  {
    [ -n "${SSH_CONNECTION:-}" ] && awk '{print $1}' <<<"$SSH_CONNECTION"
    [ -n "${SSH_CLIENT:-}" ]     && awk '{print $1}' <<<"$SSH_CLIENT"
    # sudo 清掉环境变量 → root 扫进程环境找回；cat 一把抓，2>/dev/null 容忍文件瞬时消失。
    [ "$(id -u)" = 0 ] && cat /proc/*/environ 2>/dev/null | tr '\0' '\n' \
      | sed -n 's/^SSH_CONNECTION=//p' | awk '{print $1}'
    who 2>/dev/null | sed -n 's/.*(\([0-9A-Fa-f:.]*\)).*/\1/p'
    [ -n "$ALLOW_EXTRA" ] && printf '%s\n' "$ALLOW_EXTRA"
  } 2>/dev/null | grep -vE '^$|^:0' | sort -u
}

while [ $# -gt 0 ]; do
  case "$1" in
    --binary)  BIN_SRC="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --repo)    REPO="$2"; shift 2 ;;
    --allow)   ALLOW_EXTRA="$2"; shift 2 ;;
    --force)   FORCE=1; shift ;;
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

# --- 定位二进制：--binary > 脚本同目录 > （版本判断后）下载 ---
if [ -z "$BIN_SRC" ] && [ -n "$SCRIPT_DIR" ]; then
  for cand in "$SCRIPT_DIR/ipgate-agent" "$SCRIPT_DIR/$ASSET" \
              "$SCRIPT_DIR/ipgate-agent-x86_64-unknown-linux-musl" \
              "$SCRIPT_DIR/ipgate-agent-aarch64-unknown-linux-musl"; do
    [ -f "$cand" ] && { BIN_SRC="$cand"; log "使用同目录二进制 $cand"; break; }
  done
fi

if [ -z "$BIN_SRC" ]; then
  # 没有本地二进制 → 走下载，但先判断「是否真有更新」。
  target="$VERSION"
  [ "$target" = latest ] && target="$(resolve_latest_tag)"
  installed=""
  if [ -x "$PREFIX/ipgate-agent" ]; then
    iv="$("$PREFIX/ipgate-agent" -V 2>/dev/null | awk '{print $2}')"
    [ -n "$iv" ] && installed="v$iv"
  fi
  if [ "$FORCE" != 1 ] && [ -n "$target" ] && [ "$installed" = "$target" ]; then
    log "已是最新版本 $installed —— 无更新，跳过。（--force 可强制重装）"
    # 确保服务在跑（升级判断为"无更新"也顺手把停掉的服务拉起来）。
    systemctl is-active --quiet ipgate-agent.service 2>/dev/null \
      || systemctl restart ipgate-agent.service 2>/dev/null || true
    exit 0
  fi
  if [ -n "$installed" ]; then
    log "当前 ${installed}，目标 ${target:-latest} → 开始更新。"
  else
    log "未安装 → 安装 ${target:-latest}。"
  fi
  download_binary
fi
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

# --- 防自锁：把管理来源 IP（SSH 等）加入放行名单 ---
# default-drop 一旦生效，除管理端口/established/名单/公开端口外一律拒新建连接，含 SSH！
admin_ips="$(collect_admin_ips)"
if [ -n "$admin_ips" ]; then
  warn "default-drop 启用后仅放行名单内的源 IP 可新建连接（含 SSH）。"
  while IFS= read -r aip; do
    [ -z "$aip" ] && continue
    case "$aip" in *:*) c="$aip/128" ;; *) c="$aip/32" ;; esac
    if "$PREFIX/ipgate-agent" --config "$CONF_DIR/config.json" allow "$c" --note "installer: admin/SSH"; then
      log "已放行管理来源 $c"
    else
      warn "跳过无法识别的来源: $aip"
    fi
  done <<<"$admin_ips"
else
  warn "未能自动识别管理来源 IP（sudo 清掉了 SSH_CONNECTION、curl|bash 无 tty、或本地控制台）。"
  warn "为防自锁：用 --allow <你的IP> 指定，或 sudo -E 重跑，或装完立即 ipgate-agent allow <IP>/32。"
  warn "若本机对外提供 Web 等服务，务必把 80/443 写进 config.json 的 public_tcp！"
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
systemctl enable ipgate-agent.service >/dev/null 2>&1 || true
# 用 restart 而非 enable --now：无论之前是否在跑，都拉起新二进制 —— 重复运行脚本 = 原地升级。
systemctl restart ipgate-agent.service

sleep 1
if systemctl is-active --quiet ipgate-agent.service; then
  log "服务已启动。"
else
  warn "服务未处于 active，请查看: journalctl -u ipgate-agent -e"
fi

echo
# 已有配对设备 = 升级场景，不再生成新配对码；否则首装，打印一个。
dev_count="$("$PREFIX/ipgate-agent" --config "$CONF_DIR/config.json" status 2>/dev/null \
  | sed -n 's/.*设备：\([0-9]*\).*/\1/p')"
[ -z "$dev_count" ] && dev_count=0
if [ "$dev_count" -gt 0 ] 2>/dev/null; then
  log "升级完成（已有 $dev_count 个已配对设备，无需重新配对）。"
else
  log "生成首个配对码（供客户端入网）:"
  "$PREFIX/ipgate-agent" --config "$CONF_DIR/config.json" pair || true
fi
echo
log "完成。校验 ruleset: nft list table inet ipgate"
