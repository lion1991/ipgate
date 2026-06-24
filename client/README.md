# client

跨端 GUI 客户端：一套 **Tauri 2** 代码产出 iOS / Android / Windows / macOS / Linux。

所有变更经 agent 完成，客户端**不直接操作内核**。

## 职责

- 多**主机 (Host)** 管理：主机清单、连接凭据（移动端用 Keychain / Keystore）。
- 可视化查看 / 放行 (Allow) / 撤销 (Revoke) 放行名单条目。
- 与 agent **同步 (Sync)**，展示内核实际状态与本地编辑的差异。

## 选型（规划）

- 框架：Tauri 2（Rust 核心 + WebView 前端），与同仓库 `../../nexshell` 一致。
- 前端框架：待定（Vue / React / Svelte）。
- 依赖 `proto/` 定义的协议类型。

## 待办

- [ ] `tauri init`（先桌面端跑通，再加 `tauri ios` / `tauri android`）
- [ ] 选前端框架
- [ ] 主机管理 + 凭据安全存储
- [ ] 名单编辑 UI + 同步流程
