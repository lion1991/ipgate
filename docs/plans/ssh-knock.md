# SSH 敲门实施方案（ADR 0012）

定案见 `docs/adr/0012-ssh-knock.md`。每步单独提交、可单独回滚。

## 步骤

1. **可行性验证**：✅ 2026-11-06 真机独立测试表实测通过（见 ADR 0012「验证」）。
2. **agent + proto**（agent 0.2.11）：✅ 「仅名单」开着时渲染敲门 set 与规则；敲门 / 转发门逐级降级；`AgentSettings` 上报 `ssh_knock_port` / `ssh_knock_active`；`status` 打印敲门端口；控制台 `ssh-expose --allowlist` 遇敲门被拒同样报错不改设置。
3. **客户端 core**：建 SSH 连接前敲门（IPv4 / IPv6 各一包）；派生算法与 agent 共用一组测试向量。
4. **Mac 客户端**：「安全」显示敲门端口与生效态（未生效时给「重试」）；撤销名单的自锁警告改为：敲门生效时撤销本机不会锁住管理通道。
5. **Tauri 客户端（iOS / Android）**：同 Mac。
6. **真机验收**：124.221.243.188 升级 agent，手机换网络（流量）验证能进；看 counter。

## 注意

- 云安全组要放行敲门 UDP 端口；客户端「安全」页显示端口，`ipgate-agent status` 也打印。
- 第 3 步上线前，手机端仍受「仅名单」影响，急用可临时关掉开关。
