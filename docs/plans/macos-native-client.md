# macOS 原生客户端（SwiftUI）实施方案

状态：实施中（第 1 步完成）
日期：2026-11-01
关联：ADR 0009（定案）、0007（传输）

## 目标

用 SwiftUI 做一个 macOS 27+ 原生客户端，功能与 Tauri 版对齐，系统外观（液态玻璃、侧栏、工具栏、菜单栏）全部走标准控件。Rust 核心与 Tauri 版共用。

## 目录与组件

| 目录 | 作用 |
|---|---|
| `client-core/` | 从 `client/src-tauri/src` 抽出的核心：传输、Noise、身份、密钥存储、known-hosts、各命令的业务逻辑。不依赖 Tauri |
| `client-ffi/` | UniFFI 导出层，把 `client-core` 包成 Swift 可调用的类型化接口；脚本打包成 XCFramework |
| `client/src-tauri/` | 保留，命令改成调用 `client-core` 的薄包装 |
| `mac/` | SwiftUI 工程（Bundle ID `com.ipgate.mac`，最低 macOS 27，App Sandbox） |

`client-core` 的数据目录和 Keychain service 由调用方传入：Tauri 版继续用 `com.ipgate.client`，原生版用 `com.ipgate.mac`，两边数据互不影响。

## 步骤（每步单独提交、可单独回滚）

1. **记录决策**：ADR 0009 + 本方案。✅
2. **抽出 `client-core`**：搬移模块，`AppState` 改成不依赖 Tauri 的核心对象，Tauri 命令改为薄包装。Tauri 版行为不变；验证：`client-core` 单测 + Tauri 构建。
3. **`client-ffi` + XCFramework**：UniFFI 导出全部命令，proto 类型按需加可选 `uniffi` feature（agent 不启用）。验证：生成 Swift 绑定，用一个最小 Swift 程序调通 `list_hosts`。
4. **SwiftUI 样板**：主机侧栏 + 放行名单页（含放行当前 IP、撤销确认）。用户和 Tauri 版对比观感，确认后继续。
5. **补齐其余页面**：端口转发、安全设置、设备、配对、同步、身份导入导出，原生菜单栏与快捷键。

## SDK 27 用得上的 API

- 标准控件自动适配液态玻璃、系统玻璃透明度滑块、非活动窗口样式。
- `alert` / `confirmationDialog` 的 `item:` 重载：撤销放行、删除转发、忘记主机的确认框。
- 工具栏 `visibilityPriority(_:)`：窄窗口时主操作留在栏上；`ForEach` 可直接放进 `toolbar`。
- `@State` 宏：`@Observable` 视图模型只初始化一次。

写 SDK 27 新 API 前先读 Xcode 自带的 Apple 参考：
`/Applications/Xcode.app/Contents/PlugIns/IDEIntelligenceChat.framework/Versions/A/Resources/swiftui-whats-new-27*`。

## 范围外

- App Intents / 快捷指令、菜单栏常驻图标：新功能，用户没要，不做。
- iOS 原生：不在本方案内。
