# ADR 0008：转发名单门（forward gate）

状态：已定案
日期：2026-10-14
关联：ADR 0002（ruleset 布局）、0005（端口转发）、0006（dnat 排空）、0007（SSH 唯一入口）；方案 `docs/plans/forward-allowlist-gate.md`

## 背景

`inet ipgate` 只接管 `input` hook。被 DNAT 改写目的地址后**走 forward 路径**的流量不经过放行名单，包括：
(1) ipgate native 转发（`ip ipgate_nat`）；(2) 旧 dnat 工具（`ip dnat_utils`）；(3) Docker `-p` 映射（iptables 的 `nat` 表 DNAT 到容器后走 FORWARD）。
结果是：开了 default-drop 的主机上，这三类端口仍对全网开放。

## 决策

| # | 决策 | 理由 |
|---|------|------|
| 1 | 在 **`inet ipgate` 表里加一条 `forward` base chain**，直接引用 `@allow4/@allow6/@public_tcp/@public_udp` | 同表引用，不需要跨表复制名单。放行、撤销、过期、对账都立即生效。如果放在 `ip ipgate_nat`，没有 native 转发时该表会被整体删除，门也就跟着没了 |
| 2 | 门链是**无参静态模板**（不含转发条目、网卡、解析 IP） | ADR 0005 的两表隔离防的是「转发渲染出错影响 SSH」。门链不含转发数据，风险面与 input 模板一样；`ip ipgate_nat` 仍不引用 `inet ipgate` |
| 3 | 只匹配 `ct state new ct status dnat`，**不按网卡过滤** | `ct status dnat` 能命中被任何表 DNAT 过的连接，不管来自哪个表。回包、容器出网、VPN 纯路由转发和本机 output 都不会命中。语义与 input 链一致：名单决定谁能对本机对外发布的服务发起新连接 |
| 4 | `policy accept`，末尾定点 `counter drop`，优先级 **-10** | policy accept 保证非 DNAT 流量不受影响。drop 是终局裁决，accept 不是，所以 Docker/ipgate_nat 的 accept 推翻不了门的 drop。-10 排在 Docker filter(0) 和 `ipgate_nat forward`(0) 之前，避开同优先级时顺序不确定的问题 |
| 5 | 公开端口沿用 `public_tcp/public_udp`，按 **`ct original proto-dst`**（DNAT 前的原端口）匹配，并显式写 `meta l4proto` | 不引入新概念。Docker 端口 ipgate 无从得知，按端口放行是三类转发唯一共同的口径。显式 l4proto 既满足传输层依赖，也防止 TCP 公开端口误放 UDP |
| 6 | 全局开关 `forward_allowlist_only` 存 `state.json`，**代码默认关**；关时**不渲染** forward 链 | 升级后 ruleset 与旧版逐字节相同，不会突然切断在用的转发。**全新安装**由 install.sh 执行 `forward-expose --allowlist` 开启（装机时 default-drop 本来就要求配置 public 端口，口径一致） |
| 7 | 不做启动探针；**带门 ruleset 加载失败时自动按无门模板重试**（`nft::apply_ruleset`） | `nft -f` 是原子事务，失败时内核仍是旧表，按无门模板重试就回到已知良态。门的问题绝不能拖累 input 链（SSH 入口、名单）落地。真实 apply 本身就是最准确的探针 |
| 8 | 拦截用 **drop** | 与 input 链口径一致，隐蔽性优先 |

## ruleset 片段（门开时追加在 `chain input` 之后）

```nft
chain forward {
    type filter hook forward priority -10; policy accept;
    ct state established,related accept
    ct state new ct status dnat ip saddr @allow4 accept
    ct state new ct status dnat ip6 saddr @allow6 accept
    ct state new ct status dnat meta l4proto tcp ct original proto-dst @public_tcp accept
    ct state new ct status dnat meta l4proto udp ct original proto-dst @public_udp accept
    ct state new ct status dnat counter drop
}
```

## 生效态与降级

- **意图 vs 生效**：`forward_allowlist_only` 是用户意图（持久化）。`forward_gate_active` 是内核实际状态（`Arc<AtomicBool>`），由启动、对账兜底重建、SSH/转发开关这几条整表 apply 路径回写。两者都通过 `AgentSettings` 上报，旧 agent 为 `None`。`apply_ruleset` 返回 `Gate::{Off, Active, Rejected(nft 原始错误)}`。
- **运行期开关**（RPC `set_forward_exposure`，`set_ssh_exposure` 同理）：持 store 锁，先 apply 再落盘，**任何失败都不改设置**。apply 失败时内核仍是旧表；门被拒时内核已退回无门，返回 `NftFailure` 并附 nft 原文（区分「不支持」与临时故障）。原本关着的仍是关；原本「开但未生效」的重试失败后仍是这个状态。
- **并发**：服务内的整表重建（RPC 开关、对账兜底）都持 store 锁、取最新开关，互相串行，不会拿过期开关覆盖刚落地的 ruleset。
- **启动/重建时失败**（如换了内核）：意图保留，生效态为 false。客户端显示「已开启但未生效」，提供「重试」和「关闭」，并在日志告警。
- **CLI `forward-expose`**：`--allowlist` 失败时报错（附 nft 原文）且不落盘。`--open` 用于控制台救援。成功后若服务在运行就自动 `systemctl restart`，否则服务内存里的旧开关会在下次落盘或重建时把改动撤销（`ssh-expose` 同样处理）。
- 门不经过 input hook，**开启不会锁住 SSH/管理通道**，因此不需要「名单为空则拒」。客户端只做强确认（提醒 Docker 对外服务要先加入公开端口）。
- 已建立连接不受开关切换影响（`established,related accept` 在前）。

## 验证

- 单测：门关时不含 `hook forward`；门开时逐行断言，且 input 段与门关渲染逐字节一致（与 SSH 开关正交）；`apply_ruleset` 的生效、回退、双失败；store 旧 JSON 兼容；e2e 开关流程、「内核不支持」报错且设置不变、apply 失败时开/关两个方向都不改设置、「开但未生效」重试失败保留意图且内核恢复后重试生效。
- 真实 nft（Debian trixie，nftables 1.1.3，netns 拓扑）：未放行源访问 native DNAT 和另一张表（priority -100，模拟 dnat 工具/Docker）的 DNAT 都被拦，counter 增长；放行源可达；纯路由转发不受影响；`public_tcp` 按 DNAT 前原端口放行；开门前建立的 TCP 长连接不断；重复 apply 幂等。
- **未验证**：el7（nft 0.8 + 3.10 内核）。若报错，按决策 7 自动降级为无门；但如果 0.8 只告警不报错而规则实际不生效，回退不会触发，需真机看 counter 确认。

## 不做 / 推后

- native 转发的 per-forward `public` 标记。
- `public_tcp/udp` 运行期可改（目前只能改 config 后重启）。
- 网卡豁免（如 wg0/docker 桥），可用放行私网段代替。
- reject 代替 drop。

## 风险

| 风险 | 对策 |
|------|------|
| 开门切断别人在用的公开转发/Docker 服务 | 代码默认关、升级不变；客户端强确认；已建立连接不断；公开服务写进 `public_tcp` |
| 任何经本机 DNAT 的转发流量（跨桥容器 hairpin、VPN 对端经公网 IP 访问映射端口、kube-proxy、透明代理等）开门后都受名单约束 | 与 input 语义一致；放行对应私网段或设为公开端口 |
| 外部只删掉 `inet ipgate` 的 forward 链（不删表）时，对账只看 set 元素，察觉不到，仍上报「生效」 | 属外部篡改；下次整表重建（重启/开关/对账兜底）即恢复。暂不做周期校验 |
| 老内核/老 nft 不认 `ct status`/`ct original` | 决策 7：自动退回无门，并上报未生效 |
| 门链误配伤到 SSH | 门只挂 forward hook，input 模板不变，事务原子，还有回退 |
