# ADR 0001：整体架构 — 跨端客户端 + 远程 agent + nftables

状态：草案（脚手架阶段，待评审）
日期：2026-06-23

## 背景

需要一款工具，跨移动端 / PC / Mac 管理多台 Linux 主机的 IP 放行名单。
放行名单底层用 nftables 落地。

## 决策

### 拓扑：客户端 / agent 两层

- **客户端 (Client)** 跑在用户设备上，纯 GUI，不直接接触任何被管主机的内核。
- **agent** 跑在每台被管**主机 (Host)** 上，是唯一能读写 nftables 的组件。
- 客户端经网络 API 调用 agent。

理由：移动端无法直接 SSH 进内核改 nftables；把特权操作收敛到 agent，便于鉴权、审计、最小权限（仅 agent 需要 `CAP_NET_ADMIN`）。

### 客户端技术栈：Tauri 2

一套 Rust + WebView 代码产出 iOS / Android / Windows / macOS / Linux。与本仓库既有 `nexshell`（Rust/Tauri）一致，复用经验。

### 落地层：nftables named set

放行名单落地为一个 named set（默认 `ipgate_allow`），规则只写一条 `ip saddr @ipgate_allow accept`，增删条目即增删 set 成员 —— O(1) 维护，避免逐条 rule 重排。
agent 用 `nft -j`（JSON 输出）读、用 `nft` 命令或 netlink 写。具体方式见 ADR 0002（待定）。

### 协议：共享 proto crate

客户端与 agent 共享 `proto/` 里的 serde 类型，单一可信源，避免两端结构体漂移。

## 待定（开新 ADR 决策）

- ~~**ADR 0002 nftables 落地方式**~~ → 已定案，见 [`0002-nftables-backend.md`](0002-nftables-backend.md)：`nft` 子进程 + 全主机 default-drop（独占 `inet ipgate` 表）+ 内核 timeout 兜底/agent 对账权威。
- ~~**ADR 0003 传输与鉴权**~~ → 已定案，见 [`0003-transport-auth.md`](0003-transport-auth.md)：REST/JSON over rustls(TLS 1.3) + TOFU 指纹固定 + 每设备 Ed25519 密钥/配对码 + 公网直连加硬。
- ~~**ADR 0004 agent 部署形态**~~ → 已定案，见 [`0004-deployment.md`](0004-deployment.md)：root + 静态 musl 单二进制 + systemd 防火墙提前 + 安装脚本防自锁（注入 SSH 来源 IP）。
- **多主机管理**：客户端侧主机清单、凭据存储（移动端 Keychain / Keystore）。
- **过期条目**：agent 侧定时清理 `ExpiresAt` 过期的成员（nft set 自带 timeout vs. agent 轮询）。
- **审计**：放行/撤销操作日志留在 agent 侧。

## 影响

- 安全边界明确：特权只在 agent。客户端被攻破最多拿到 token，可在 agent 侧吊销。
- agent 必须先在单台 VPS 上独立跑通（不依赖客户端），便于测试与早期手动验证。
