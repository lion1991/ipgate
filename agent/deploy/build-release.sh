#!/usr/bin/env bash
#
# 交叉编译静态 musl 单二进制到 dist/。
#
# 推荐用 cross（容器化，免在本机搭 musl 工具链）:
#   cargo install cross --git https://github.com/cross-rs/cross
# 需要 Docker / Podman 可用。
#
# 用法: ./build-release.sh            # 用 cross（默认）
#       BUILDER=cargo ./build-release.sh   # 改用本机 cargo（需自备 musl 链接器）
#
set -euo pipefail

# 切到 workspace 根（deploy 的上两级：agent/deploy -> agent -> ipgate）。
WS_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WS_ROOT"

BUILDER="${BUILDER:-cross}"
TARGETS=("x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl")
OUT="$WS_ROOT/dist"
mkdir -p "$OUT"

command -v "$BUILDER" >/dev/null 2>&1 || {
  echo "未找到 $BUILDER。装 cross: cargo install cross --git https://github.com/cross-rs/cross" >&2
  exit 1
}

for t in "${TARGETS[@]}"; do
  echo ">> 构建 $t"
  "$BUILDER" build --release --target "$t" -p ipgate-agent
  cp "target/$t/release/ipgate-agent" "$OUT/ipgate-agent-$t"
  echo "   -> $OUT/ipgate-agent-$t"
done

echo "完成。把 dist/ipgate-agent-<arch>、deploy/*.service、deploy/*.sh、deploy/config.example.json 一起拷到目标主机，运行 install.sh。"
