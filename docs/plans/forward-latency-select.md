# 端口转发多目标按延迟选择实施方案（ADR 0014）

定案见 `docs/adr/0014-forward-latency-select.md`。每步单独提交、可单独回滚。

## 步骤

1. **proto + agent**（agent 0.2.13，先以预发布发出）：
   - proto：`ForwardRule` / `AddForwardRequest` 增额外目标列表与可选 TCP 探测端口（`serde(default)`，旧 state 原样读）；校验每个目标的端口段、纯 UDP 规则必须有探测端口；`ForwardView` 增各目标状态与上次切换信息。
   - agent：独立探测线程（5 秒一轮，各目标并发 connect）维护内存里的健康与延迟窗口；选择逻辑按 ADR 0014 决策 5–7 写成纯函数；选中目标变化时触发 `apply_now`，与 API、`resolve_loop` 的落地串行；`resolve_one` 对选中目标解析与做禁区检查。
   - 判挂切走时经 ctnetlink dump 并按回程源过滤后逐条删除 conntrack 记录（决策 9），失败只告警。
   - CLI：`forward-add` 可重复给 `--target host[:port]` 与 `--probe-port`；`forwards` 打印各目标状态。
2. **客户端 core + ffi**：暴露多目标、探测端口与目标状态字段；旧 agent 提示升级（≥ 0.2.13）。
3. **Mac 客户端**（AppKit，ADR 0010）：编辑页增删目标、纯 UDP 时必填探测端口；列表与详情显示各目标延迟、存活、当前在用、上次切换时间与原因。
4. **发布**：自己的主机先装预发布试用，没问题再转正式版。

## 验证

- 单元：选择函数（判挂立即切、全挂停在原目标、延迟差不够 20% / 10ms 不切、不够 60 秒不切、恢复计数）；校验（纯 UDP 缺探测端口、目标端口段形状）；ctnetlink 报文编解码。
- e2e（netns）：两个后端，杀主后端约 15 秒后新连接走另一个；给一个后端加 `tc netem` 延迟，60 秒后切到快的；UDP 持续发包时杀当前目标，确认 conntrack 被删、流量改走存活目标。
- 回归：单目标规则渲染的 nat 表与 0.2.12 逐字节一致。
