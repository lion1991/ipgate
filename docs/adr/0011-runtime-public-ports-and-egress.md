# ADR 0011：公开端口运行期可调 + 主机出口 IP 探测

状态：已定案
日期：2026-11-05
关联：ADR 0002（ruleset 布局、`public_tcp/public_udp`）、0007（SSH 唯一入口）、0008（转发名单门按公开端口放行）

## 背景

用户要在客户端：(1) 看到主机自己往外连时的公网出口 IP；(2) 按端口对全部 IP 放行。

`public_tcp/public_udp` 两个 set 从 ADR 0002 起就有，但端口只能写在 agent 的 `config.json` 里，客户端看不到也改不了。主机出口 IP 方面，agent 只能读网卡地址，云主机上一般是内网地址。

## 决策

| # | 决策 | 理由 |
|---|------|------|
| 1 | 客户端添加的公开端口存 `state.json`（`public_ports`，带协议 tcp/udp/both 与备注），落地时与 `config.json` 的**合并**；config 里的在客户端标「配置文件」、删不掉 | 不迁移、不改写现有配置文件，升级零行为变化；两处来源都可见 |
| 2 | 增删走整表重建（`apply_ruleset`），先落内核再落盘，失败不改存储 | 与 SSH 暴露、转发名单门同一套顺序与锁 |
| 3 | 渲染时排序合并重叠 / 相邻区间 | interval set 内联重叠元素会被 nft 拒；config 与客户端添加的可能重叠 |
| 4 | SSH「仅名单可连」时拒绝覆盖 SSH 端口的 TCP 公开端口；反过来，公开端口覆盖 SSH 端口时拒绝开启「仅名单可连」（RPC 与控制台 `ssh-expose` 都查）。新增时只查新加的那条，config.json 里遗留的冲突不拦无关端口 | 用户拍板：SSH 暴露只在「安全」里管。否则开关显示「仅名单」，实际却对全网开放 |
| 5 | 同 `(协议, 端口)` 再加只改备注 | 与放行名单「同目标覆盖」一致，不出重复项 |
| 6 | 出口 IP 由 agent 并发问 icanhazip.com、api64.ipify.org、ifconfig.me，v4 / v6 按解析出的地址族分别建连，各取最先返回的有效结果，总时长 5 秒；一族探到后另一族最多再等 1 秒 | 用户要求用成熟的公共检测服务；三家都有 A + AAAA。宽限 1 秒：v6 有地址但不通时不拖满 5 秒，同一连接上的其他请求也不会被它排队太久 |
| 7 | 出口探测走明文 HTTP/1.0，不引 TLS | agent 不带 TLS 栈；结果只用于展示、不参与放行，被篡改也只影响显示 |

公开端口同样作用于转发名单门（ADR 0008 按 DNAT 前原端口匹配），语义保持「这个端口谁都能连」。

## RPC

- `egress_ip` → `EgressIp { ipv4?, ipv6? }`（要发网络请求，由连接循环异步处理，不进同步 dispatch）
- `list_public_ports` → `Vec<PublicPort>`（config 的在前，`from_config = true`）
- `add_public_port(PublicPortRequest)` / `remove_public_port { proto, ports }` → 最新列表

旧 agent 不认这些 op，回「请求解析失败」，客户端据此提示升级（agent ≥ 0.2.10）。
