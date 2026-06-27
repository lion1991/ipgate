# ipecho

返回调用方公网 IP 的极简服务，行为对标 `curl ip.sb`。

ipgate 的配套小工具：把自己的 IP 加进**放行名单**前，先 `curl https://你的域名/`
拿到出口 IP。纯标准库，无依赖。

## 运行

```sh
go run .                 # 默认监听 :8080
go run . -addr :9000     # 换端口
```

| 参数 / 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `-addr` / `IPECHO_ADDR` | `:8080` | 监听 `host:port` |
| `-trusted-proxies` / `IPECHO_TRUSTED_PROXIES` | `0` | 前方可信反代层数；`>0` 才解析 `X-Forwarded-For` |

## 接口

| 路径 | 返回 |
| --- | --- |
| `GET /` | 纯文本 IP + 换行（curl/浏览器）；带 `?format=json` 或 `Accept: application/json` 时返回 JSON |
| `GET /json` | 始终 JSON：`{"ip":"1.2.3.4","family":"ipv4"}` |
| `GET /healthz` | `ok` |

```sh
curl https://你的域名/            # 1.2.3.4
curl https://你的域名/json        # {"ip":"1.2.3.4","family":"ipv4"}
```

## 关于代理头（重要）

返回的 IP 可能被拿去**放行**，所以绝不能信任客户端伪造的 `X-Forwarded-For`。

- **默认 `-trusted-proxies 0`**：忽略一切代理头，只认 TCP 连接来源。直接对公网暴露时用这个。
- **跑在反代后面**：用 `-trusted-proxies N` 声明前方**恰好** N 层可信代理（nginx/Caddy/CDN）。
  服务会从 `X-Forwarded-For` 右侧数到第 N 跳之外取真实客户端——右侧 N 个条目是可信代理写的，
  客户端只能伪造更左侧的，骗不进来。链路长度不符则回退到连接来源。

  nginx 单层示例：

  ```nginx
  location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
  ```

  配 `-trusted-proxies 1`。
