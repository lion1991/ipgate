# ipgate

跨平台的 **Linux 服务器 IP 放行名单**管理工具。

客户端（移动端 / PC / Mac）连接运行在远程 Linux 主机上的 **agent**，可视化地查看、增删、批量管理基于 **nftables** 的 IP 放行名单（allowlist）。

## 组成

| 目录 | 角色 | 技术栈 | 说明 |
|------|------|--------|------|
| [`client/`](client/) | 客户端 | Tauri 2 + Rust + WebView | 一套代码出 iOS / Android / Windows / macOS / Linux 包。GUI 管理界面。 |
| [`agent/`](agent/) | 服务端 | Rust 守护进程 | 跑在远程 Linux 主机上，落地 nftables 规则，对客户端暴露 API。 |
| [`proto/`](proto/) | 协议 | Rust crate（serde） | 客户端与 agent 共享的请求/响应类型，单一可信源。 |

```
┌─────────────────────────┐         TLS / 鉴权          ┌──────────────────────────┐
│  client (Tauri 2)       │  ───────── API ──────────▶  │  agent (远程 Linux 主机)  │
│  移动端 / PC / Mac      │  ◀──── 规则 / 状态 ───────  │  落地 nftables 规则       │
└─────────────────────────┘                             └──────────────────────────┘
         共享 proto/（serde 类型）            内核 nft set: ipgate_allow
```

## 核心概念

- **放行名单 (Allowlist)**：被允许访问的 IP / CIDR 集合，落地为 nftables 的一个 named set。
- **条目 (Entry)**：名单中的一条，含 IP/CIDR、备注、过期时间（可选）。
- **agent**：远程主机上的服务端进程，唯一有权改动 nftables 的组件。
- **客户端 (Client)**：跨端 GUI，所有操作通过 agent 完成，自身不直接碰内核。

术语以 [`CONTEXT.md`](CONTEXT.md) 为准。架构决策见 [`docs/adr/`](docs/adr/)。

## 状态

🚧 脚手架阶段。各组件目录下的 `README.md` 记录了选型与待办，尚未开始编码。

## 开发起步（规划）

1. `proto/` 先定协议类型（条目、名单、操作、错误）。
2. `agent/` 实现 nftables 落地 + API，可在一台测试 VPS 上单独跑通。
3. `client/` 用 Tauri 2 起 GUI，先打通桌面端，再补移动端。
