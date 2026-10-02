#!/bin/sh
# 把目录里的文件全部挂到 $TAG 的 Forgejo release 上：没有 release 就建，同名附件先删再传，重跑幂等。
# 环境变量：TOKEN / SERVER / REPO / TAG，可选 NOTES（release 说明）。改自 meshgate 的同名脚本。
# 用法：upload-release-assets.sh <目录>
set -eu

DIR="${1:?用法: upload-release-assets.sh <目录>}"
if [ -z "${TOKEN:-}" ]; then
	echo "没有拿到令牌：实例没有向工作流注入 GITHUB_TOKEN。请在仓库 Secrets 里加一个"
	echo "有 write:repository 权限的令牌，并把工作流 env 里的 TOKEN 改成引用它。"
	exit 1
fi
api="$SERVER/api/v1/repos/$REPO"
resp=$(mktemp)
assets=$(mktemp)

# req METHOD URL [curl 参数…]：响应体落 $resp，状态码进 $code 并打到日志——失败时要看得出是哪一步。
req() {
	m="$1"; u="$2"; shift 2
	code=$(curl -sS -o "$resp" -w '%{http_code}' -X "$m" -H "Authorization: token $TOKEN" "$@" "$u")
	echo "$m $u -> HTTP $code" >&2
}
# JSON 用 node 解析（跑 JS action 的 runner 必有 node）；sed 贪婪匹配会抓到 author 里的 id。
release_id() {
	node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(d&&d.id!=null?String(d.id):"")' "$resp" 2>/dev/null || true
}

req GET "$api/releases/tags/$TAG"
id=$(release_id)
if [ -z "$id" ]; then
	echo "该 tag 还没有 release，创建中…"
	body=$(node -e 'const e=process.env;process.stdout.write(JSON.stringify({tag_name:e.TAG,name:e.TAG,body:(e.NOTES||"")+"\n\n校验和见 SHA256SUMS。"}))')
	req POST "$api/releases" -H "Content-Type: application/json" -d "$body"
	id=$(release_id)
fi
if [ -z "$id" ]; then
	echo "创建 release 失败，服务端返回："; cat "$resp"; echo
	echo "HTTP 401/403 = 令牌没有写权限；404 = 仓库路径不对（$REPO）。"
	exit 1
fi
echo "release id=$id"

req GET "$api/releases/$id/assets"
cp "$resp" "$assets"
for f in "$DIR"/*; do
	[ -f "$f" ] || continue
	name=$(basename "$f")
	old=$(node -e '
		const a=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
		const hit=(Array.isArray(a)?a:[]).find((x)=>x.name===process.argv[2]);
		process.stdout.write(hit?String(hit.id):"");
	' "$assets" "$name" 2>/dev/null || true)
	[ -z "$old" ] || req DELETE "$api/releases/$id/assets/$old"
	echo "上传 $name"
	req POST "$api/releases/$id/assets?name=$name" -F "attachment=@$f"
	case "$code" in
	2??) ;;
	*) echo "上传 $name 失败，服务端返回："; cat "$resp"; exit 1 ;;
	esac
done
echo "完成：$SERVER/$REPO/releases/tag/$TAG"
