# ipgate

跨平台的 **Linux 服务器 IP 放行名单**管理工具。

客户端（移动端 / PC / Mac）连接运行在远程 Linux 主机上的 **agent**，可视化地查看、增删、批量管理基于 **nftables** 的 IP 放行名单（allowlist）。

**安装 agent**：见 [`agent/README.md` 的「安装」](agent/README.md#安装)。

## 组成

| 目录 | 角色 | 技术栈 | 说明 |
|------|------|--------|------|
| `client/` | 客户端 | Tauri 2 + Rust + WebView | 一套代码出 iOS / Android / Windows / Linux 包，macOS 用原生版（AppKit + SwiftUI）。GUI 管理界面。客户端源码不公开。 |
| [`agent/`](agent/) | 服务端 | Rust 守护进程 | 跑在远程 Linux 主机上，落地 nftables 规则，对客户端暴露 API。 |
| [`proto/`](proto/) | 协议 | Rust crate（serde） | 客户端与 agent 共享的请求/响应类型，单一可信源。 |

```
┌─────────────────────────┐                             ┌──────────────────────────┐
│  client                 │  ── SSH 隧道 + Noise ───▶  │  agent (远程 Linux 主机)  │
│  移动端 / PC / Mac      │  ◀──── 规则 / 状态 ──────  │  落地 nftables 规则       │
└─────────────────────────┘                             └──────────────────────────┘
         共享 proto/（serde 类型）            内核 nft set: ipgate_allow
```

## 核心概念

- **放行名单 (Allowlist)**：被允许访问的 IP / CIDR 集合，落地为 nftables 的一个 named set。
- **条目 (Entry)**：名单中的一条，含 IP/CIDR、备注、过期时间（可选）。
- **转发名单门**：可选开关。开启后，被 DNAT 进来的新建连接（端口转发、Docker 映射端口）也只放行名单内 IP 与公开端口（ADR 0008）。
- **agent**：远程主机上的服务端进程，唯一有权改动 nftables 的组件。
- **客户端 (Client)**：跨端 GUI，所有操作通过 agent 完成，自身不直接碰内核。

术语以 [`CONTEXT.md`](CONTEXT.md) 为准。架构决策见 [`docs/adr/`](docs/adr/)。
