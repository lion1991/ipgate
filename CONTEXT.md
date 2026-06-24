# ipgate

ipgate 的术语表。本文件约束相关概念的用词，不记录实现细节。

## Language

### 名单与条目

**放行名单 (Allowlist)**：
被允许访问受保护端口/服务的 IP 集合。落地为内核 nftables 的一个 **named set**（默认名 `ipgate_allow`）。
_Avoid_: 白名单（口头同义，canonical 词是「放行名单」）、黑名单（语义相反，本工具只做放行）

**条目 (Entry)**：
放行名单中的一条记录。含 **目标 (Target)**（单个 IP 或 CIDR）、**备注 (Note)**、**过期时间 (ExpiresAt，可选)**。
_Avoid_: 规则（规则指 nftables rule，是 agent 落地后的产物，不是用户编辑的单位）

**目标 (Target)**：
条目所指的地址，可为 IPv4/IPv6 单地址或 CIDR 段。
_Avoid_: 地址（不够精确，可能与主机地址混淆）

### 组件

**agent**：
跑在**远程 Linux 主机**上的服务端进程。**唯一**有权读写 nftables 的组件。对客户端暴露 API，把条目落地为 nftables set 成员。
_Avoid_: 服务端（口头同义）、守护进程（实现形态，非角色名）

**客户端 (Client)**：
跨端 GUI（移动端 / PC / Mac，Tauri 2）。所有变更经 agent 完成，自身**不直接操作内核**。
_Avoid_: app、前端（前端特指 client 内的 WebView 层）

**主机 (Host)**：
被管理的一台远程 Linux 服务器。一个客户端可管理多台主机，每台主机跑一个 agent。
_Avoid_: 服务器、机器（口头同义，canonical 词是「主机」）

### 操作

**放行 (Allow)**：
向放行名单**新增**一个条目（把目标加入 nft set）。
_Avoid_: 添加、加白

**撤销 (Revoke)**：
从放行名单**移除**一个条目。
_Avoid_: 删除（删除指条目记录的删除；撤销强调放行权限被收回）

**同步 (Sync)**：
把客户端编辑后的名单状态与 agent 上的内核实际状态对齐，并报告差异。
_Avoid_: 刷新、拉取（同步是双向对齐，不只是单向读）

### 落地层

**named set (nft set)**：
nftables 中的具名地址集合，放行名单的内核落地形态。agent 通过它批量匹配，而非逐条 rule。

**落地 (Apply)**：
agent 把条目变更写入内核 nftables 的动作。
_Avoid_: 生效、提交
