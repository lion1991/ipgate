# SSH 敲门实施方案（ADR 0012）

定案见 `docs/adr/0012-ssh-knock.md`。每步单独提交、可单独回滚。

## 步骤

1. **可行性验证**：✅ 2026-11-06 真机独立测试表实测通过（见 ADR 0012「验证」）。
2. **agent + proto**（agent 0.2.11）：✅ 「仅名单」开着时渲染敲门 set 与规则；敲门 / 转发门逐级降级；`AgentSettings` 上报 `ssh_knock_port` / `ssh_knock_active`；`status` 打印敲门端口；控制台 `ssh-expose --allowlist` 遇敲门被拒同样报错不改设置。
3. **客户端 core**：✅ 建 SSH 连接前敲门（IPv4 / IPv6 各一包）；派生算法与 agent 共用一组测试向量。
4. **Mac 客户端**：「安全」显示敲门端口与生效态（未生效时给「重试」）；撤销名单的自锁警告改为：敲门生效时撤销本机不会锁住管理通道。
5. **Tauri 客户端（iOS / Android）**：同 Mac。
6. **真机验收**：✅ 2026-11-06 自用测试机（agent 0.2.11）+ Android 0.5.6 走流量验证能进（详见 ADR 0012「验证」）；iOS 真机待测。
7. **敲门日志**（ADR 0012 决策 10）：✅ agent 渲染 ok / bad / ssh 三类 nft 日志规则，`status` 打印查看命令；OrbStack 测试表验证命中次数。待真机确认 journal 里的日志文本。

## 注意

- 云安全组要放行敲门 UDP 端口；客户端「安全」页显示端口，`ipgate-agent status` 也打印。
- agent 0.2.11 先以预发布发出，第 6 步验收通过后 2026-11-06 转正式（`latest`）。测试机连不上 GitHub，用本机下载的发布包整包安装。
- 第 3 步上线前，手机端仍受「仅名单」影响，急用可临时关掉开关。
