#!/bin/sh
# 这台 Forgejo 的 Linux runner（标签 go：Debian 容器、root）不带 Rust：装 stable 最小工具链 +
# musl 目标与链接器，并把依赖指纹写进 step 输出 `deps`，给 actions/cache 作 key。
set -eu

SUDO=$(command -v sudo || true)
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq musl-tools >/dev/null

command -v cargo >/dev/null 2>&1 ||
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
PATH="$HOME/.cargo/bin:$PATH" rustup target add x86_64-unknown-linux-musl
echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"

# 指纹 = Cargo.lock 去掉本仓库自己的包（每次发版都改版本号），只随第三方依赖变化。
# 必须全小写：act_runner 的缓存服务会把 key 小写化，带大写的 key 永远判「未命中」、每次重传整包。
echo "deps=$(awk 'BEGIN { RS = ""; ORS = "\n\n" } !/name = "ipgate-/' Cargo.lock | sha256sum | cut -c1-16)" >> "$GITHUB_OUTPUT"
