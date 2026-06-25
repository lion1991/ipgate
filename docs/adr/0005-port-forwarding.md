# ADR 0005：端口转发（DNAT/SNAT）

状态：已定案
日期：2026-06-25
关联：ADR 0002（nftables 落地）、ADR 0003（传输与鉴权）

## 背景

agent 除了放行名单，还要能把本机某端口的流量转发到另一台 host:port（经典的 `本地端口>网卡>目标:端口>源` 端口转发）。已有一个独立工具 `dnat`（Go）做这件事，但把它当二进制联动会带来「双语言、双发布、机器接口偏弱、做不到与放行名单联动」的代价。决定 **agent 原生实现**，把 `dnat` 的实战经验（域名重解析、范围映射、source=auto、ip_forward）移植过来。

## 决策

| 维度 | 选择 |
|------|------|
| 落地机制 | **`nft` 子进程文本**（复用 ADR 0002 的 `nft -f` 路径），不走 netlink |
| 表布局 | **独立 `ip ipgate_nat` 表**，与放行名单的 `inet ipgate` **彻底隔离** |
| 应用方式 | **整表全量原子重建**（`table; delete table; table {…}`），规则少且 DNS 重解析后需整体换 |
| 域名 | `dest_host` 可为域名，agent **周期重解析**；解析失败**回退上次成功 IP**（动态域名不断流） |
| SNAT 源 | `source=auto` 取出口网卡首个 IPv4；显式 IP 漂移出网卡时回退当前网卡 IP |
| 抽象 | 落地层封装为 `NatBackend` trait（`apply_nat` / `flush_nat`），与 `NftBackend` 并列、互不耦合 |

## 为什么独立表（最关键）

nftables 的 set/chain **按表隔离**。把转发放进**独立的 `ip ipgate_nat` 表**，意味着：

- 转发的 DNAT/SNAT 渲染哪怕出错、整表被 `delete table` 重建，也**碰不到** `inet ipgate` 里的管理端口放行不变量（ADR 0003 的 bootstrap 最高优先级）。
- 转发落地失败**绝不拖垮主服务**：启动期 `forward::apply_now` 失败只记日志，放行名单与管理端口照常工作。

## 详细设计

### 表结构（`ip ipgate_nat`）

```
chain prerouting  { type nat hook prerouting  priority -100; policy accept;
  iifname "eth0" tcp dport 443 dnat to 1.2.3.4:8443 }
chain postrouting { type nat hook postrouting priority 100;  policy accept;
  ip daddr 1.2.3.4 tcp dport 8443 snat to <源IP> }
chain forward     { type filter hook forward  priority 0;    policy accept;
  ct state established,related accept
  iifname "eth0" ip daddr 1.2.3.4 tcp dport 8443 ct state new accept }
```

优先级用**数字**（-100/100/0）而非 `dstnat`/`srcnat` 命名 —— 命名优先级要 nft 0.9+，数字在 el7 的 0.8 也认（与放行名单表口径一致）。`forward` 链 policy accept；显式 accept 既表意，也作为日后「只放名单内源 IP」的挂点。

### 解析 / 落地编排（`forward.rs`）

1. `resolve_all`：读 store.forwards → 每条解析（网卡 = 显式或默认路由；目标 IP = 解析或回退上次；源 = auto/显式/漂移回退）。
2. `commit`：空则 `flush_nat`；否则 `ensure_ip_forward`（写 `/proc` + sysctl.d 持久化）+ `apply_nat`；成功后回写解析缓存（**失败不回写**，保留上次良态）。
3. `apply_now`（API/启动期）：立即解析 + 落地一次。
4. `resolve_loop`（独立线程）：周期重解析，用解析结果 hash **跳过无变化**的轮次，域名 IP 漂移后自动重建。

### API / CLI

```
GET/POST /v1/forwards        列出 / 新增（需 Bearer）
DELETE   /v1/forwards/{id}   删除（需 Bearer）
GET      /v1/interfaces      列网卡（客户端下拉/源 IP 提示，需 Bearer）

ipgate-agent forwards | forward-add | forward-rm    离线/装机/排障（同 allow/revoke 语义）
```

存储：`State` 增 `forwards`、`forward_revision`、`resolved`（解析缓存，供 DNS 失败回退跨重启）。

## 安全注记

- **转发端口天然对全网开放**：流量走 forward hook，**不过** `inet ipgate` 的 INPUT 名单。这是端口转发的标准语义。
- **「只放名单内源 IP」推后（Phase 2）**：要在 `ip ipgate_nat` 里同步一份名单副本（跨表 set 不可引用），有复杂度。v1 先做标准转发，挂点已在 `forward` 链留好。

## v1 范围

IPv4；单端口 + 等长区间 + 区间→单端口；TCP/UDP/Both；IP 与域名目标。IPv6、名单门绑定、mTLS 纵深留后续。
