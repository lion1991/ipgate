# ADR 0006：dnat 适配与排空（统一查看/删除，逐条迁移）

状态：已定案（实现中）
日期：2026-06-25
关联：ADR 0005（端口转发 native 落地）、ADR 0002（nftables 落地）、ADR 0003（鉴权）

## 背景

外部工具 `dnat`（Go，仓库 `work/tools/dnat`）也在做端口转发，且**必须继续独立存在**：它在别的机器上单独部署、有用户经它的 TUI 管理。它是一个 systemd daemon，**独占** `ip dnat_utils` 表，每 60s 从 `/etc/dnat/conf` 重新解析域名并重建该表（见其 `apply.go`/`daemon.go`）。

诉求：让 ipgate 客户端能**统一查看、删除**本机 dnat 创建的转发，而**新增走 ipgate 自己的 native 后端**（`ip ipgate_nat`，ADR 0005）。配合「逐条迁移」，把 ipgate 管的机器上的 dnat 规则**渐进排空**到 native；dnat 工具本身在别处照常独立活。

## 决策

| 维度 | 选择 |
|------|------|
| 模型 | **排空（drain）**：dnat 规则只读+删+迁移，新增只进 native，逐条手动迁移 |
| 落地权 | dnat 仍是 `dnat_utils` 的**唯一落地者**；ipgate **绝不直接写内核 dnat 表** |
| 集成点 | dnat 的**磁盘契约**：读 `conf`/`state.json`，删按 PrefixKey 改 `conf`（持 `conf.lock`）+ 触发 `dnat apply` |
| 并发 | 与 dnat/TUI 共写 `conf`：`flock(conf.lock)` 互斥（与 dnat `lock.go` 同语义）+ 原子 tmp+rename |
| 共存优先级 | ipgate native prerouting 由 `-100` **错位到 `-90`**：dnat(`-100`) 永远先匹配 → 共存确定、迁移零瞬断 |
| 碰撞 | native 新增前扫 dnat conf，`(网卡, listen)` 撞则拒；列表对双表重叠打冲突标 |
| 抽象 | `ForwardBackend` trait；`DnatAdapter` 实现**只读+删**（`upsert` 拒绝，加走 native） |

## 排空模型（核心）

客户端看到一个**合并列表**，按来源给不同能力：

| 来源 | 能力 | 落在哪 |
|------|------|--------|
| `origin=ipgate` | 增 / 删 / 改 | `ip ipgate_nat`（agent 管，ADR 0005） |
| `origin=dnat` | 查看 / 删除 / **迁移到 agent** | `ip dnat_utils`（dnat daemon 管） |

**逐条、手动、用户说了算**：dnat 规则原地不动、继续由 dnat 管，直到用户在那条上点「迁移到 agent」。dnat 规则**不可在 ipgate 里编辑**——「改」等于「删 + 在 native 重建」，正好就是迁移。

## 为什么不直接写内核 dnat 表

dnat daemon 每 60s 从 `conf` 重建 `dnat_utils` 并自解析域名。ipgate 若直接写该表，下一 tick 即被冲掉；若 ipgate 也解析域名，则双解析打架。故 ipgate 只动 dnat 的 **conf 文件**（其唯一真源）再触发应用，让 dnat 当唯一 applier+resolver。

## 优先级错位（迁移零瞬断 + 共存确定）

两表过渡期并存，prerouting 同在 `-100` 会顺序未定义、静默打架（见会话分析）。把 ipgate native 的 prerouting 改到 **`-90`**（postrouting 对应错到 dnat 之后）。nftables prerouting 按优先级升序执行，`-100` 先于 `-90`：

- **共存**：只要 dnat 规则在，它先匹配并赢——行为确定（不是未定义）。
- **迁移**：先在 native(`-90`)建好（此刻 dnat 仍赢，**零抖动**）→ 再删 dnat conf 行 + `dnat apply`（包落到 native，**零瞬断**）。

> 实现改点：`nft/nat.rs` 的 prerouting `-100`→`-90`、postrouting `100`→更靠后；同步改其断言测试。

## 集成边界（dnat 磁盘契约——当 API 用，须钉版本）

来自 dnat 的 `paths.go`/`config.go`/`state.go`/`lock.go`：

- `conf`：`/etc/dnat/conf`，行格式 `本地端口[-段]>网卡>远端:端口[-段]>源`，`#` 注释，`source` 为 `auto`|IPv4。
- `state.json`：`/etc/dnat/state.json`，含 `lastError` 与 `entries[]`（已解析 `remoteIP`/`sourceIP`）。ipgate 据此判 `active`/取解析 IP。
- 锁：`/etc/dnat/conf.lock`，`flock(LOCK_EX)`。ipgate 读改写 conf 前必须持有它。
- 应用：`dnat apply --conf <path>`（同步；`unchanged`/`applied` 均 exit 0，非零=失败带 stderr）。
- PrefixKey = `本地端口段>网卡>`（含结尾 `>`），同 `(端口段,网卡)` 唯一——删除/去重按它。

## 字段映射（dnat → native，**无损**）

| dnat conf | native `AddForwardRequest` |
|-----------|----------------------------|
| 本地端口[-段] | `listen` |
| 网卡 | `iface = Some(..)`（conf 必有具体网卡名） |
| 远端主机 | `dest_host` |
| 远端端口[-段] | `dest_port` |
| `auto`/IPv4 | `source = Auto`/`Ip` |
| （永远 tcp+udp） | `proto = Both` |
| （无 id/note/created_by） | native 新生成；`note="迁移自 dnat"` |

方向无损：dnat 永远 tcp+udp → `Both` 忠实；dnat 无元数据可丢。（反向 native→dnat 才有损，故只做这一个方向。）

## 碰撞检测（含拦不住的缺口）

- native 新增前扫 dnat `conf`/`state`，`(网卡, listen)` 重叠则拒：「该端口已被 dnat 规则占用，请先迁移或换端口」。
- 合并列表里任何同时出现在两表的 `(网卡,端口)` 打冲突标。
- ⚠️ **缺口**：dnat TUI 用户加规则时不知道 `ipgate_nat` 存在，可能撞上 native 规则，ipgate 拦不住、发现不了。优先级错位让此情形**确定（dnat 赢）**而非未定义——这是排空过渡期能给的最好兜底。

## 终局

最后一条 dnat 规则迁走/删掉后 `conf` 空，该机 `dnat uninstall`：`dnat_utils` 消失，native 独占——**渐进、操作员驱动地走到 ADR 0005 的 native 独管**。dnat 工具在别的机器照常独立活。

## 不变量与风险

- **一台机一个权威落地者**：过渡期两表并存但 native 优先级更低让 dnat 赢；严禁两者都「权威新增」同端口。
- **公开/私有边界不破**：ipgate（公开 agent 仓）只**运行期读写 dnat 文件 + 调其二进制**，非代码依赖；dnat 仍是独立私有工具。但其 conf/state 格式是外部契约，须文档化 + 钉版本，dnat 改格式要回看本 ADR 与 `dnat/conf.rs`。
- **dnat 不在则降级**：`DnatAdapter::present()`（二进制 + conf 目录在）为假时，适配器静默不参与，native 照常。默认 `enabled=false`。

## 实现落点（已落地）

- `agent/src/dnat/`：`conf.rs`（conf 行/state.json 解析）、`lock.rs`（flock 与 dnat 互斥）、`mod.rs`（`ForwardBackend` trait + `DnatAdapter` 读/删 + `dnat_rule_to_add_request` 迁移映射 + `DnatAdapterConfig` + `encode_key`/`decode_key`）。
- `config.rs`：`AgentConfig.dnat: DnatAdapterConfig`（默认关）。
- `nft/nat.rs`：prerouting `-90`、postrouting `110`（错开 dnat 的 `-100`/`100`）。
- `proto`：`ErrorCode::Conflict`、`ForwardOrigin`/`ForwardCaps`/`UnifiedForwardView`/`UnifiedForwardList`。
- API（`api/mod.rs` + `handlers.rs`）：
  - `GET /v1/forwards` 改返回 `UnifiedForwardList`（native + dnat 合并，跨来源回填 `conflict`）。
  - `POST /v1/forwards` native 新增前做 dnat 碰撞检测（撞 → `409 Conflict`）。
  - `DELETE /v1/forwards/dnat/{key}` 删 dnat 规则（key = base64url 的 PrefixKey）。
  - `POST /v1/forwards/dnat/{key}/migrate` 迁移（先建 native 再撤 dnat，撤失败不回滚）。
- CLI：`dnat-forwards` / `dnat-migrate --listen --iface` / `dnat-rm --listen --iface`（离线操作 conf + 触发 `dnat apply`）。
- 测试：`dnat/conf.rs` 解析、`dnat/mod.rs` 键往返 + 迁移映射 + upsert 拒绝；`e2e` 统一列表形状。

### 仍待办（非本次范围）

- 客户端（私有仓）UI：展示 `origin`/`caps`/`conflict`、「迁移到 agent」按钮、调用上面两个 dnat 端点。
- native 后端正式套 `ForwardBackend` trait（目前 handler 用 `DnatAdapter` 固有方法，trait 暂作文档化抽象）。

## 代码评审已修正（xhigh 多代理评审）

- **删除按 PrefixKey 精确匹配**（曾用裸 `starts_with`：部分前缀如 `8000` 会误删多条）。`remove_rule_lines` 解析每行比 `prefix_key()`，注释/空行/不可解析行原样保留；`removed` 由是否真删到行决定（不靠文本 diff，免 CRLF/缺尾换行误判）。
- **迁移核实生效**：`apply_now` 对解析失败的条目只跳过仍返回 `Ok`，故迁移后显式核对 `resolved_ip(id).is_some()`；未生效则回滚僵尸 native、**保留 dnat**（守住零瞬断）。
- **迁移防覆盖**：目标 `(网卡,端口)` 已有 native 规则则拒（否则 `add_forward` 按 `(iface,listen)` 静默覆盖它）。
- **迁移校验端口**：dnat 允许、native 表达不了的映射（单监听→目标区间）迁移前 `validate_ports` 拒绝。
- **删除即提交**：conf 写成功即视作删除已提交（dnat daemon ≤60s 对账），即时 `dnat apply` 失败仅记日志、不再误报 500。
- **`active` 按条判**：改用 state.json 是否有该条 entry，不再被全局 `lastError` 一次失败 tick 拖成「全部 inactive」。
- **parser 对齐 dnat**：两侧都是区间时长度须相等（同 `config.go`），免把 dnat 会跳过的行当实时规则 → 幻影冲突。
- **CLI `forward-add` 补碰撞闸**：与 HTTP 对齐，守「同端口不双权威」。

## 已知限制（评审记录，暂不处理）

- **统一列表换型破坏旧客户端**：`GET /v1/forwards` 由 `ForwardList` 改 `UnifiedForwardList`（非加字段）。本工具单人运维、客户端与 agent 同步升级、且该特性本就需客户端改造，故接受；非滚动升级安全。
- **`dnat apply` 在 async handler 内同步阻塞**：与既有 native 路径（`add/remove_forward` 也同步跑 `nft`）一致，未单独 `spawn_blocking`；要改应整体改。
- **native-vs-native 区间重叠未检**：`store.add_forward` 仅按 `(iface,listen)` 精确去重，重叠（非全等）区间仍可并存——**本特性之前即如此**，非本次引入。
- **dnat daemon 在途 apply 竞态**：daemon 读旧 conf 后释放 conf.lock 再解析（≤6s/条），其间我方删 conf 可能被它用旧规则集回写；下一 tick（≤60s）自愈。此为 dnat 工具设计固有（其 TUI 同样），我方无法单边消除。
