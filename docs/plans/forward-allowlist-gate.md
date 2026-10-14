# 转发名单门：让 DNAT 进来的新建连接受放行名单约束

状态：已实施（定案见 ADR 0008；与原稿的出入见文末「实施记录」）
日期：2026-10-14
关联：ADR 0002（ruleset 布局）、0005（端口转发）、0006（dnat 排空）、0007（SSH 唯一入口）

## 1. 背景与目标

`inet ipgate` 只接管 `input` hook。凡是被 DNAT 改写目的地后**经 forward 路径**进入的流量都不过名单：
(1) ipgate native 转发（`ip ipgate_nat`，prerouting -90）；(2) 旧 dnat 工具（`ip dnat_utils`，-100）；(3) Docker `-p` 映射（iptables-nft/legacy 的 `nat` 表 DNAT 到容器，再走 FORWARD）。

目标：新增一个**可开关**的「转发名单门」，使上述三类「外部入向、被 DNAT 的新建连接」只有名单内源 IP（或公开端口）可建立；不影响回包、容器出网、VPN 路由转发、本机 output；默认关、升级零行为变化；任何失败都不触碰 SSH 自锁不变量。

## 2. 关键决策

| # | 决策 | 理由 |
|---|------|------|
| D1 | 门放在 **`inet ipgate` 表里新增 `forward` base chain**，直接引用 `@allow4/@allow6/@public_tcp/@public_udp` | 同表引用免去跨表 set 副本与同步（增删/过期/reconcile 自动生效）；且 `ip ipgate_nat` 在无 native 转发时会被整表 flush，门若放那里会在「只有 Docker/dnat 转发」时消失 |
| D2 | 两表隔离初衷不破：门链是**无参静态模板**（不含任何转发条目、网卡名、解析 IP） | 隔离要防的是「转发渲染出错碰到 SSH」；门链不含转发数据，风险面与现有 input 模板相同；`ip ipgate_nat` 依旧不引用 `inet ipgate` |
| D3 | 匹配 `ct state new ct status dnat`，**不做 iifname 过滤** | `ct status dnat` 精确命中「被任何表 DNAT 过的连接」（Docker/dnat/native 一视同仁）；回包（established）、容器出网（无 dnat 位）、WireGuard 纯路由转发（无 dnat）、本机 output（不经 forward）天然不命中。语义与 input 链一致：名单 = 谁能向本机对外发布的服务发起新连接，不区分网卡 |
| D4 | 链 `policy accept` + 末尾定点 `drop`，优先级 **-10** | policy accept 保证非 DNAT 流量零影响；drop 终局、accept 不终局，故无论 Docker FORWARD / `ipgate_nat forward` / dnat 怎么 accept 都拦得住；-10 避开与 Docker filter(0)、`ipgate_nat forward`(0) 同优先级的未定义顺序，并让未放行包在到达它们之前就被丢（counter 可读） |
| D5 | **全局运行期开关** `forward_allowlist_only`，存 store，**默认 false**；关闭时**不渲染** forward 链 | 复用 `ssh_allowlist_only` 这套链路；升级后 ruleset 与今天逐字节相同，不会突然断别人在用的转发；按条目粒度推后（会把转发增删与 inet 表重渲染耦合） |
| D6 | 公开端口沿用现有 `public_tcp/public_udp`，在门里按 **`ct original proto-dst`**（DNAT 前的原始目的端口）放行 | 零新概念：「对全世界开放的端口」自然涵盖转发监听端口；Docker 端口 ipgate 不知道、按条目标记做不到，按端口是唯一统一口径。native 的 per-forward `public` 标记可作 Phase 2（合并进同一 set） |
| D7 | ~~启动探针~~ **已取消**：只保留 D8 的失败回退，生效态由真实 apply 结果回写 `forward_gate_active` | 真实 apply 就是最准确的探针；少一条代码路径，也不会出现「探针过了真表却失败」的分叉 |
| D8 | 任何门链 apply 失败 → **自动按无门模板重试** | `nft -f` 事务原子，失败时内核仍是旧表；重试无门模板 = 回到今天的已知良态；SSH input 链从头到尾不变 |

## 3. ruleset 改动（`agent/src/nft/ruleset.rs`）

`cfg.forward_allowlist_only == true` 时在 `chain input {…}` 之后追加：

```nft
chain forward {
    type filter hook forward priority -10; policy accept;
    ct state established,related accept
    # 仅管「被 DNAT 过的新建连接」；其余转发流量（容器出网、VPN 路由）policy accept 放过
    ct state new ct status dnat ip saddr @allow4 accept
    ct state new ct status dnat ip6 saddr @allow6 accept
    ct state new ct status dnat meta l4proto tcp ct original proto-dst @public_tcp accept
    ct state new ct status dnat meta l4proto udp ct original proto-dst @public_udp accept
    ct state new ct status dnat counter drop
}
```

要点：
- `meta l4proto` 必须显式写（`ct … proto-dst` 需要传输层依赖，且避免 TCP 公开端口误放 UDP）。
- `ct status dnat` 是位测试：native 同时 DNAT+SNAT 的连接也命中。
- `nat.rs` 的 `forward` 链保持不动，仅改注释：「只放名单内源 IP」的挂点已被 ADR 0008 取代（门在 `inet ipgate`）。

兼容性判断（el7 尚未真机核实，D8 回退兜底）：`ct status` 与 `ct original proto-dst` 内核侧属 nf_tables 初版 uapi（3.13，el7 回移内核含）；nft 用户态 `ct status` 0.4+、`ct original …` 0.6+，0.8 应可解析。数字优先级、同表多 base chain、inet_service set 均已在现有口径内。

## 4. 各层改动点

### proto
- `proto/src/ruleset.rs` `RulesetConfig`：加 `#[serde(default)] forward_allowlist_only: bool`（Default false）。
- `proto/src/rpc.rs`：`RpcRequest::SetForwardExposure { allowlist_only: bool }`；`AgentSettings` 加 `#[serde(default)] forward_allowlist_only: Option<bool>`（意图）与 `#[serde(default)] forward_gate_active: Option<bool>`（内核实际生效），None = 旧 agent。

### agent
- `agent/src/store.rs`：`State` 加 `#[serde(default)] forward_allowlist_only: bool`；新增 `RulesetFlags { ssh_allowlist_only, forward_allowlist_only }` 与 `Store::ruleset_flags()`、`set_forward_allowlist_only()`（返回 changed）。
- `agent/src/config.rs`：`ruleset_with(&self, flags: RulesetFlags)` 取代单 bool；更新调用点：`main.rs` 的 `PrintRuleset`、`run` 启动 apply、`reconcile_loop` 兜底重建、`ssh_expose_cli`；`handlers.rs::set_ssh_exposure`。
- `agent/src/nft/ruleset.rs`：按 §3 渲染。
- `agent/src/nft/mod.rs`：新增 `apply_ruleset(backend, cfg, entries) -> Result<bool /*门是否生效*/>`：门开 → 先按原样 apply，失败则 `warn!` 并以 `forward_allowlist_only=false` 重试（D8）。
- `agent/src/main.rs`：`forward_gate_active: Arc<AtomicBool>` 由 `apply_ruleset` 回写（启动 / 兜底重建 / 设置切换）。新增 CLI `forward-expose --open | --allowlist`（镜像 `ssh_expose_cli`，控制台救援用）；`status` 打印门状态。
- `agent/src/api/handlers.rs`：`build_settings` 补两字段；新增 `set_forward_exposure(st, allowlist_only)`：持 store 锁，先 `apply_ruleset` 再落盘；apply 失败或门被拒（已回退无门）都不改设置，返回 `NftFailure` 并附 nft 原文（内核因原子失败仍是旧表，状态一致）。无需「名单为空拒绝」——不会自锁（管理走 SSH input），但客户端要强确认。
- `agent/src/api/mod.rs`：`dispatch` 加 `SetForwardExposure`（`tracing::warn!` 审计，同 SSH 那组）；`AppState` 加 `forward_gate_active`。
- `agent/src/e2e.rs`：`forward_exposure_toggle_flow`（默认 false → 开 → 切 SSH 门仍在 → 关）、`forward_exposure_rejected_when_kernel_lacks_support`（MockNft 拒门 → 报错、设置不变、内核为无门 ruleset）。
- `agent/deploy/install.sh`：全新安装（`config_fresh=1`）执行 `ipgate-agent forward-expose --allowlist`，失败只告警。版本 bump 0.2.8。

### client
- `client/src/api.ts`：`AgentSettings` 加 `forward_allowlist_only?: boolean | null`、`forward_gate_active?: boolean | null`；`setForwardExposure(host_id, allowlist_only)`。
- `client/src-tauri/src/commands.rs`：`set_forward_exposure` 命令 → `RpcRequest::SetForwardExposure`；`lib.rs` 注册。
- `client/src/views/security.ts`：SSH 行下追加转发门行（复用 `statusRow`/`confirmSheet`），三态——关（warn「转发端口对全网开放」）、开（ok「转发仅名单可连」）、开但 `forward_gate_active!==true`（warn「转发名单门未生效」）；收紧确认文案：涉及 ipgate 转发、dnat 工具、Docker 映射，已建立连接不受影响，公开服务需先加公开端口；旧 agent（字段 undefined）隐藏该行。
- `client/src/state.ts` / `views/sidebar.ts`：摘要加 `forwardRestricted`（实际生效态）；侧栏只在该主机有转发时提示「转发对全网开放」，免得无转发的主机被刷屏。概览「名单与转发」卡片副标题附门状态。
- `client/src/views/forward.ts`：列表顶部一行提示当前门状态，点击跳安全分区。

## 5. 迁移与默认值

- store 字段 `serde(default)` → 老 `state.json` 读出 false；门关时渲染结果与现版本**逐字节相同**（单测断言）→ 升级零行为变化。
- 已建立连接：开关切换都不掐断（`established,related accept` 在前），与 SSH 开关一致。
- 名单变化（放行/撤销/过期/reconcile 增删 set 元素）对门**即时生效**且无需额外动作——同一 set。reconcile 只动 set 元素，不会 revert 门链；其 `list()` 失败兜底重建读 `store.ruleset_flags()`，不丢门。
- 旧客户端连新 agent：`AgentSettings` 多字段无影响；新客户端连旧 agent：字段缺省，隐藏开关。
- 公开端口：`public_tcp/udp` 仍是静态 config（运行期不可改）；Docker 用户要开放某映射端口需改 config 重启（见 Q3）。

## 6. 测试计划

单测（`ruleset.rs`）：
- 默认 cfg：不含 `hook forward`；与 `forward_allowlist_only=false` 的渲染完全相等。
- 开门：含 `type filter hook forward priority -10; policy accept;`、四条 accept、`ct state new ct status dnat counter drop`；drop 位于所有 accept 之后；`chain forward` 之前的文本与关门渲染逐字节相等（input 链不变量未被触碰）；与 `ssh_allowlist_only` 两两组合正交。
- `apply_ruleset`：门生效 / 门被拒回退无门（保留 SSH 开关）/ 门关只 apply 一次 / 无门也失败时报错。
- `store.rs`：缺字段 JSON 反序列化 → false。`config.rs`：`ruleset_with(flags)` 透传。
- `nat.rs` 既有断言 `!contains("inet ipgate")` 继续成立。
- e2e：toggle flow；内核拒门时报错且设置不变；apply 失败不改设置；「开但未生效」重试。

真机验证（一台带 Docker 的 VPS + 一台 el7）：
1. 基线：`docker run -d -p 8080:80 nginx`；native `forward-add --listen 9443 --dest <lan>:443`；（有则）一条 dnat 规则。未放行 IP 三者均可达。
2. `forward-expose --allowlist`（或客户端开关）：未放行 IP 三者超时，`nft list chain inet ipgate forward` 的 counter 增长；放行 IP 可达；切换过程中已建 TCP 会话不断。
3. 不误伤：容器内 `curl https://example.com`、同桥容器互访、本机 `curl 127.0.0.1:8080` 与 `curl <公网IP>:8080`、WireGuard 对端经本机纯路由转发——全部正常。
4. 公开端口：config `public_tcp` 加 8080 → 重启 → 未放行 IP 可达 8080，9443 仍拦。
5. 名单动态：撤销/TTL 到期后，该 IP 新连接即刻被拦，无需重渲染。
6. IPv6：Docker 开 `ip6tables` 时，`allow6` 内外 IP 行为对称。
7. el7 nft 0.8：看启动日志有无回退告警；`print-ruleset` 输出过 `nft -c -f`；若不支持：客户端显示不支持、开关被拒、ruleset 无 forward 链。
8. 失败回退：人为改坏门链模板（测试分支）→ 启动日志出现回退告警，`nft list ruleset` 仍有完整 input 链，SSH 全开模式下未放行 IP 始终可连 SSH。
9. 救援：`ipgate-agent forward-expose --open` 立即恢复。

## 7. 风险

| 风险 | 对策 |
|------|------|
| el7 nft 0.8 不认 `ct status`/`ct original` | apply 失败回退无门模板；settings 上报 `forward_gate_active=false` |
| 跨桥容器 hairpin / VPN 对端经本机公网 IP 访问映射端口被拦 | 与 input 链语义一致（这些源访问本机服务同样要进名单）；文档写明：放行该私网段或把端口设为公开。Phase 2 可选 `forward_gate_exempt_ifaces` |
| 开启后把别人在用的转发断掉 | 默认关；客户端强确认并显示受影响条数；已建连接不断 |
| 门链误配伤到 SSH | 门只在 forward hook；input 模板不变；事务原子；回退模板；单测断言 input 段逐字节不变 |
| Docker 自身 FORWARD policy drop 拦掉放行流量 | 既有行为，与门无关（Docker 对自己的 -p 有 accept）；文档提示 |

## 8. 文档同步

- **新增 ADR 0008**《转发名单门（forward gate）》：D1–D8 全部决策、ruleset 片段、与 Docker/dnat/ipgate_nat 的多 base chain 交互说明、兼容性与降级。
- ADR 0002：§2「`forward` v1 不接管」→ 改为「forward hook 仅挂可选名单门（policy accept），见 ADR 0008」；ruleset 示例追加 forward 链（标注可选）；「待定 / 推后」划掉「forward 链 / NAT 场景」。
- ADR 0005：「安全注记」改写——转发端口默认全开仍是 v1 语义，但「只放名单内源 IP」已由 ADR 0008 在 `inet ipgate` 实现，不需要跨表 set 副本；表结构节 `forward` 链「挂点」注释改为「历史保留，门不在此」；「v1 范围」的「名单门绑定留后续」划掉。
- ADR 0006：补一句 dnat_utils 的转发同样受门约束（`ct status dnat` 与表无关）。
- AGENTS.md 索引登记 ADR 0008；README「核心概念」补一行转发名单门。
- `nat.rs` 模块注释与 forward 链注释更新。

## 9. 分步实施顺序

1. proto：`RulesetConfig`/`AgentSettings`/`RpcRequest` 字段 + 测试。
2. `ruleset.rs`：先写单测再实现门链渲染。
3. store `RulesetFlags` + `config.ruleset_with(flags)` + 全部调用点；`apply_ruleset` 回退函数；`main.rs` 启动/reconcile/`forward-expose` CLI/`status`。
4. handlers + dispatch + AppState；e2e toggle 测试。
5. client：api.ts → commands.rs/lib.rs → security.ts 三态行 → sidebar/state → forward.ts 提示。
6. 文档：ADR 0008、0002/0005/0006 修订、AGENTS.md、README、nat.rs 注释。
7. deploy：install.sh 全新安装开门、版本 bump 0.2.8；按 §6 真机验证（含 el7）。

## 已定（原「待拍板」）

1. 全新安装默认开门：代码默认 false（升级安全），install.sh 对全新安装执行 `forward-expose --allowlist`。
2. native 转发的 per-forward `public` 标记：推后（Phase 2）。
3. `public_tcp/udp` 运行期可改：本期不做。
4. 拦截动作：drop。
5. `forward_gate_exempt_ifaces`：本期不做，靠放行私网段替代。

## 实施记录

- 取消 D7 探针，只保留 D8 回退；`AgentSettings` 上报的是 `forward_gate_active`（实际生效），不是 `forward_gate_supported`。
- Fable 代码审查后修正：RPC 开关改为「持锁、先 apply 再落盘、失败不改设置」（原稿是「先落盘、门被拒再回滚」，apply 整体失败时会留下不一致）；`apply_ruleset` 返回 `Gate`，错误附 nft 原文；对账兜底重建持锁读最新开关；CLI 救援成功后自动重启运行中的服务；客户端「未生效」态提供「重试」和「关闭」。
- 已在 Docker（Debian trixie，nftables 1.1.3，netns 拓扑）用真实 nft 验证 §6 第 2、3（纯路由部分）、4 项，并验证了长连接不断和重复 apply 幂等。带 Docker 的真实 VPS 和 el7 尚未验证。
