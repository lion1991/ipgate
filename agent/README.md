# agent

跑在**远程 Linux 主机**上的服务端进程，唯一有权读写 nftables 的组件。

## 职责

- 对客户端暴露 API：REST/JSON over rustls(TLS 1.3)，TOFU 指纹 + Ed25519 鉴权（[ADR 0003](../docs/adr/0003-transport-auth.md)）。
- 把放行名单落地到 nftables：`nft` 子进程，全主机 default-drop，独占 `inet ipgate` 表（[ADR 0002](../docs/adr/0002-nftables-backend.md)）。
- 读取内核实际状态，支持与客户端**同步 (Sync)**。
- 清理过期条目（agent 对账权威 + 内核 timeout 兜底），记录放行/撤销审计日志。

## 模块

面向内核的半边（ADR 0002）：

| 模块 | 内容 |
|------|------|
| `nft` | `NftBackend` trait + `NftCli`（`nft` 子进程）；`ruleset.rs` 渲染原子事务、`parse.rs` 解析 `nft -j` |
| `config` | `AgentConfig`（bind、mgmt_port、public_tcp/udp、data_dir）+ `validate()` 拒自锁 |
| `store` | 条目/设备 JSON 持久化（原子写）+ allow/revoke/prune/设备管理 |
| `reconcile` | 期望态 vs 内核态求 `Diff`（missing/stale/expired） |

面向客户端的半边（ADR 0003）：

| 模块 | 内容 |
|------|------|
| `tls` | 自签证书 load-or-generate（rcgen）+ SPKI SHA-256 指纹（TOFU） |
| `auth` | `keys`（Ed25519 验签）/ `token`（HMAC 会话令牌）/ `challenge`（单次 nonce）/ `pairing`（配对码，文件跨进程）/ `access`（管理端口访问密钥门） |
| `api` | axum 路由 + `AppState` + `serve`（over rustls）+ `AuthDevice` Bearer 抽取器 + **访问密钥门 / per-IP 限流中间件** + 错误→HTTP 映射 |
| `main` | CLI：`run`（守护进程）/ `pair` / `access-key` / `print-ruleset` / `status` / `uninstall` |

## CLI

```sh
ipgate-agent --config <path> pair            # 生成配对口令（启用密钥门时为「访问密钥.配对码」join 串）+ 打印 SPKI 指纹
ipgate-agent --config <path> access-key      # 打印管理端口访问密钥（--reset 轮换；轮换后需 restart）
ipgate-agent --config <path> run             # 守护进程：应用 ruleset + 后台对账 + TLS API（需 root + nftables）
ipgate-agent --config <path> allow <CIDR>    # 离线放行（写存储，安装时防自锁用；运行中请走 API）
ipgate-agent --config <path> revoke <CIDR>   # 离线撤销
ipgate-agent --config <path> print-ruleset   # 打印将应用的 nft ruleset（不改内核，便于审计）
ipgate-agent status                          # 存储条目 + 内核 set 状态
ipgate-agent uninstall                       # flush 掉 inet ipgate 表
```

## 部署（ADR 0004）

`deploy/` 下：systemd unit、配置样例、安装/卸载/构建脚本。

```sh
deploy/build-release.sh          # cross 交叉编译静态 musl 二进制 → dist/
# 把 dist/ipgate-agent-<arch> + deploy/* 拷到目标主机后：
sudo deploy/install.sh           # root；探测 ufw/firewalld、注入 SSH 来源 IP 防自锁、起服务、打印配对码
sudo deploy/uninstall.sh --purge # 停服务 + flush 表 + 删数据
```

> ⚠️ default-drop 一旦生效，除管理端口 19186/established/放行名单/公开端口外**一律拒（含 SSH）**。install.sh 会自动把当前 SSH 来源 IP 加入名单防止锁死。

## API（over rustls，默认 19186）

> **访问密钥门**（`require_access_key`，全新安装默认开）：所有请求须带 `X-Ipgate-Key: <访问密钥>`，
> 否则一律裸 **404**——端口对外「变暗」，扫描器识别不出 ipgate。门挡在路由前；另叠 per-IP 限流（429）。
> 升级既有部署默认**不开**（保现有客户端不被挡）；开启见 config `require_access_key`。

```
POST /v1/pair            配对入网（验签 + 消费配对码）
POST /v1/auth/challenge  取 nonce
POST /v1/auth/verify     验签换会话令牌
GET/POST/DELETE /v1/allowlist   列出 / 放行 / 撤销   （需 Bearer）
POST /v1/sync            内核 vs 存储差异          （需 Bearer）
GET  /v1/devices         已授权设备               （需 Bearer）
DELETE /v1/devices/{id}  吊销设备                 （需 Bearer）
GET  /healthz            存活探针
```

## 开发

```sh
cargo test                  # 42 项：含完整 配对→挑战→验签→放行→撤销 端到端流程 + 访问密钥门/限流
cargo clippy --all-targets
cargo run -- --config <cfg> print-ruleset   # 非 Linux 可跑（纯渲染）
cargo run -- --config <cfg> pair            # 非 Linux 可跑（生成证书+配对码）
```

## 待办

- [x] 定 ADR 0002 / 0003
- [x] 面向内核：`NftBackend` + 幂等重建（坐实不变量）+ 对账 / 存储 / 配置
- [x] 面向客户端：TLS+TOFU + 鉴权（配对/挑战-应答/会话令牌）+ REST API（axum）
- [ ] 定 ADR 0004（部署形态）；systemd unit + 安装脚本（`CAP_NET_ADMIN`、探测 ufw/firewalld、flush 选项）
- [ ] 在一台测试 VPS 上跑通 `run` + 用真实客户端打通配对/放行
- [x] 管理端口加硬：访问密钥门（端口「变暗」）+ per-IP 限流（ADR 0003 §4）
- [x] 名单外 IP 禁 ping（ICMP echo 仅放名单源；PMTUD 错误类仍放，防黑洞）
- [ ] fail2ban 式连续失败锁定 / 审计日志 / 实时同步 WebSocket；mTLS 双向证书（防御纵深）
