# ADR 0002：nftables 落地方式与 ruleset 布局

状态：已定案
日期：2026-06-23
关联：ADR 0001（整体架构）、ADR 0003（传输与鉴权 —— 管理端口不变量来自此）

## 背景

agent 需要把放行名单条目落地到内核 nftables，并维持"别把自己锁在门外"的不变量（ADR 0003）。本 ADR 定三件事：用什么机制操作 nftables、ruleset 长什么样、过期条目怎么清。

## 决策

| 维度 | 选择 |
|------|------|
| 落地机制 | **`nft` 子进程**：读用 `nft -j`(JSON)，写用 `nft -f -`(stdin 喂事务，原子、无 shell、无注入)与 `nft add/delete element` |
| 主机角色 | **全主机 default-drop**：ipgate 接管 `input` hook，策略 drop；放行 established/loopback/必要 ICMP/管理端口/公开端口/名单源 |
| 过期清理 | **两者都用**：agent 自管对账为**权威**，内核 set `timeout` 为**尽力而为**的兜底自动删除 |
| 抽象 | 落地层封装为 `NftBackend` trait，agent 业务逻辑/API 不依赖具体实现，便于日后换 netlink |

## 详细设计

### 1. 落地机制：`nft` 子进程

- **读**：`nft -j list set inet ipgate allow4`（结构化 JSON），用于 Sync 读取内核实际状态。
- **写（增量）**：`nft add element ...` / `nft delete element ...`，单条原子。
- **写（重建/引导）**：构造完整事务文本，`nft -f -` 经 **stdin** 喂入，整份原子落地。
- **绝不经 shell**：用 `std::process::Command` 传参向量 / stdin，杜绝注入；输入(IP/CIDR/端口)在 proto 层严格类型校验。
- **可审计**：管理员可 `nft list ruleset` 亲自核对；审计日志直接记录等效 nft 操作。
- **trait 抽象**：

```rust
trait NftBackend {
    fn bootstrap(&self, cfg: &RulesetConfig) -> Result<()>;   // 原子建表/集/链
    fn add(&self, e: &Entry) -> Result<()>;
    fn remove(&self, target: &IpNet) -> Result<()>;
    fn list(&self) -> Result<Vec<KernelElement>>;             // 读内核真实态
    fn reconcile(&self, desired: &[Entry]) -> Result<Diff>;   // 对账 + 清过期
}
```

### 2. ruleset 布局（全主机 default-drop）

ipgate 独占一张 `inet` 表，**自有 base chain**，用户只能改 set（名单/公开端口），**改不到 base chain**——这从结构上保住了不变量。

```nft
table inet ipgate {
    set allow4      { type ipv4_addr;   flags interval, timeout; }   # 放行名单 v4(支持 CIDR)
    set allow6      { type ipv6_addr;   flags interval, timeout; }   # 放行名单 v6
    set public_tcp  { type inet_service; flags interval; }           # 对全世界开放的 TCP 端口(默认空)
    set public_udp  { type inet_service; flags interval; }

    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept       # 回包/已建连，必须最先放
        ct state invalid drop
        iif lo accept                            # 本地回环，必须放，否则本机服务崩

        # 必要 ICMPv6：不放则 IPv6 直接瘫(邻居发现/RA/PMTUD)
        ip6 nexthdr icmpv6 icmpv6 type {
            nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert,
            echo-request, echo-reply, destination-unreachable, packet-too-big,
            time-exceeded, parameter-problem } accept
        ip protocol icmp icmp type {
            echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept

        tcp dport 19186 accept                   # 管理端口：无条件放行(ADR 0003 不变量)，永不进名单

        tcp dport @public_tcp accept             # 公开端口(如 web 80/443)，可配
        udp dport @public_udp accept

        ip  saddr @allow4 accept                 # 放行名单：允许的源 IP 获得访问
        ip6 saddr @allow6 accept

        # policy 已是 drop；可选： log prefix "ipgate-drop " counter
    }
}
```

设计要点：
- **`output` 不接管**（默认 accept）：保证主机能主动外联（agent 自身、系统更新等）。
- **`forward` v1 不接管**：仅在路由/NAT 场景需要，留作后续配置项。
- **v4/v6 分两个 set**（`inet` family 下 set 类型不能混 v4/v6）。
- **`flags interval`** 让 set 支持 CIDR/区间。
- **放行名单语义**：名单源 IP 获得（除公开端口外其余端口的）访问；**每条目按端口细分**留作 v2。

### 3. 不变量：别把自己锁在门外（default-drop 下尤为致命）

- 管理端口(19186)的 accept 是 **base chain 里的字面规则**，不来自任何用户可改的 set——**没有任何 API 能移除它**。
- base chain 重建走 `nft -f -` **单事务**：default-drop 与管理端口 accept 同一原子内生效，绝无"drop 已开、accept 未上"的窗口。
- agent 启动即**幂等重建** base chain，每次开机重新坐实不变量。
- 可选安全网（v1.1）：base chain 变更走 `iptables-apply` 式**定时自动回滚**——N 秒内未确认则还原,防坏 ruleset 锁死。鉴于管理端口恒开,此为锦上添花。

### 4. 过期清理：两者都用

- set 带 `flags timeout`；有 `ExpiresAt` 的条目以 per-element timeout 落地 → 内核到期自动删，**尽力而为**。
  - 注意：`interval + timeout` 在较老内核上有兼容坑，故内核侧仅作兜底,**不作权威**。
- agent 周期 **reconcile**(权威)：读内核真实态 → 删除已过期条目并同步清理其元数据(备注等内核不存的信息) → 重新坐实 base chain 不变量。
- 这样新内核享受内核自动删、老内核靠 agent 轮询，都不漏。

### 5. 持久化与重启

- **内核规则随表常驻**：agent 进程停止/升级期间防火墙照常生效(规则在内核，不在进程)。
- **agent 启动重建**：以自身存储为准，幂等重建 table/set/chain 并载入条目——不依赖 `/etc/nftables.conf`，开机即对齐。
- **卸载**：提供选项 flush 掉 `inet ipgate` 表(否则规则留在内核、无人可改)。

### 6. 与现有防火墙共存（重要警示）

- default-drop 是**权威**的：nftables 中 **drop 裁决终局**，ipgate 一旦 drop，其它表(ufw/firewalld)的 accept 救不回来；反之亦然。
- 故 default-drop 模式下 **ipgate 应是唯一防火墙管理者**。
- 安装时 agent **探测 ufw/firewalld** 是否启用 → 警示并建议停用，避免裁决互相打架产生迷惑行为。

## 选型（crate）

| 用途 | 方案 |
|------|------|
| 调 nft | `std::process::Command`（参数向量 / stdin，无 shell） |
| 解析 nft JSON | `serde_json`（`nft -j` 输出） |
| 输入校验 | proto 层 `IpNet`/端口类型，拒非法 |
| （后续可换）netlink | `rustables` / `nftnl`，藏在 `NftBackend` 之后 |

## 风险与对策

| 风险 | 对策 |
|------|------|
| 把自己锁死 | 管理端口字面 accept 不可删 + 单事务原子 + 开机重建 + 可选定时回滚 |
| IPv6 瘫痪 | base chain 固定放行必要 ICMPv6(ND/RA/PMTUD) |
| 与 ufw/firewalld 冲突 | 探测并警示;default-drop 模式建议独占 |
| `interval+timeout` 老内核坑 | 内核 timeout 仅兜底,agent 对账为权威 |
| nft JSON schema 漂移 | 仅依赖稳定字段;`NftBackend` 隔离,出问题可换 netlink |
| nft 命令注入 | 不经 shell + proto 强类型校验 |

## 影响 / 后续

- **驱动 proto**：`Entry` 需 `target: IpNet`(支持 CIDR)、`expires_at`；新增 `RulesetConfig`(public_tcp/udp、mgmt_port)、`KernelElement`、`Diff`。
- **驱动 ADR 0004(部署)**：agent systemd 需 `CAP_NET_ADMIN`、开机早于网络服务重建 ruleset、卸载脚本 flush 选项、安装时探测 ufw/firewalld。
- **default-drop 是强默认**：文档需醒目提示"接管整机防火墙"，安装流程要二次确认。

## 待定 / 推后

- 每条目按端口细分放行（v2）。
- `forward` 链 / NAT 场景。
- base chain 变更的定时自动回滚安全网（v1.1）。
- 公开端口 ICMP echo 是否默认放行（隐蔽性 vs 可运维性）。
