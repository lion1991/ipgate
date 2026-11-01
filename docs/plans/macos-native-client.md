# macOS 原生客户端（SwiftUI）实施方案

状态：实施中（第 4 步完成，待用户对比观感）
日期：2026-11-01
关联：ADR 0009（定案）、0007（传输）

## 目标

用 SwiftUI 做一个 macOS 27+ 原生客户端，功能与 Tauri 版对齐，系统外观（液态玻璃、侧栏、工具栏、菜单栏）全部走标准控件。Rust 核心与 Tauri 版共用。

## 目录与组件

全部在 `client/` 下。`client/` 被本公开仓库 `.gitignore` 排除，由其中独立的本地 git 仓库管理（无 remote），客户端代码绝不进公开仓库。

| 目录 | 作用 |
|---|---|
| `client/core/` | `ipgate-client-core`：从 `src-tauri/src` 抽出的核心——传输、Noise、身份、密钥存储、known-hosts、各命令的业务逻辑。不依赖 Tauri，独立 Cargo workspace |
| `client/ffi/` | UniFFI 导出层，把 core 包成 Swift 可调用的类型化接口；脚本打包成 XCFramework |
| `client/src-tauri/` | 保留，命令改成调用 core 的薄包装 |
| `client/mac/` | SwiftUI 工程（Bundle ID `com.ipgate.mac`，最低 macOS 27，App Sandbox） |

core 的数据目录和 Keychain service 由调用方传入：Tauri 版继续用 `com.ipgate.client`，原生版用 `com.ipgate.mac`，两边数据互不影响。

## 步骤（每步单独提交、可单独回滚）

1. **记录决策**：ADR 0009 + 本方案。✅
2. **抽出 core**：✅ 搬移模块，`AppState` 改成不依赖 Tauri 的核心对象，Tauri 命令改为薄包装。Tauri 版行为不变；验证：core 单测 + Tauri 构建。
3. **ffi + XCFramework**：✅ UniFFI 导出全部命令（`IpgateClient`）。给 Swift 用的 Record 在 ffi 里单独定义、由 proto/core 类型转换，**不给 proto 加 uniffi feature**——公开仓库零改动，类型也按 Swift 习惯设计（IP/CIDR/id 用字符串，时间用 `Date`）。`ffi/build-xcframework.sh` 产出 `ffi/out/IpgateFFI.xcframework` + `ipgate_ffi.swift`；`ffi/smoke/run.sh` 是 Swift 冒烟测试。
4. **SwiftUI 样板**：✅ `client/mac/`（xcodegen 生成工程，`project.yml` 为准；预构建脚本自动跑 `ffi/build-xcframework.sh`）。主机侧栏（搜索）+ 放行名单页（Table、添加、放行本机、撤销确认、右键菜单、Delete 键）+ 右侧「访问与安全」inspector（本机出口 IP 是否已放行）+ 粘贴文本导入身份。文案沿用 Tauri 版。用户先在 Tauri 版导出身份、在原生版导入，对比观感后再做第 5 步。
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

## 踩过的坑

- **构建 ffi 时不要设 `MACOSX_DEPLOYMENT_TARGET`**：它也作用于宿主机的过程宏，rustc 1.92 按 27.0 链出的 dylib dyld 加载不了（`mis-aligned LINKEDIT string pool`），表现为 `can't find crate for serde_derive` 一类错误。已经生成的坏产物要 `cargo clean --release -p <宏 crate>` 清掉。
- **Swift Record 不要叫 `Host`**：和 Foundation 的 `Host` 类重名，主机记录叫 `HostInfo`。
- **modulemap 不用 `--xcframework`**：那会生成 `framework module`，而我们打的是静态库 XCFramework；模块名须为 `ipgate_ffiFFI`（生成的 Swift 源码按这个名字 import）。
- **Swift 6.4 编译器在带标签元组的 `compactMap` 推断上会崩**（`failed to produce diagnostic for expression`）：改用小 struct。
- **视图 body 里会写入的缓存（如每主机页面模型字典）标 `@ObservationIgnored`**：否则在视图更新中改了被观察状态。
