# macOS 原生客户端（SwiftUI）实施方案

状态：实施中（4a 完成，下一步 4b）
日期：2026-11-01
关联：ADR 0009（定案）、0007（传输）

## 目标

用 SwiftUI 做一个 macOS 27+ 原生客户端，功能覆盖 Tauri 版，系统外观（液态玻璃、侧栏、工具栏、菜单栏）全部走标准控件。Rust 核心与 Tauri 版共用。

**界面不照搬 Tauri，按工具的实际用途重新设计**（用户拍板，2026-11-01）。

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
   - **4a 访问状态**：✅ 启动时并发刷新全部主机；侧栏状态图标 + 摘要；名单页「本机未放行」横幅；inspector 加 SSH 状态；「放行本机到全部主机」。
   - **4b 名单表格**：标出覆盖当前出口的条目、列排序、多选批量撤销（一次确认）、「+」改为锚定弹出框。
   - **4c 菜单栏图标 + 出口 IP 变化通知**。
5. **补齐其余页面**：端口转发、安全设置、设备、配对、同步、身份导出/二维码；工具栏分段控件切换分区，同步、导出放「⋯」菜单。

## 界面设计决策

按使用频率设计：最常见的是「出口 IP 变了进不去 → 放行本机」，其次是清理名单，转发/安全/设备/配对/同步是偶尔操作。

- **侧栏图标只回答「我进得去吗」**：绿 = 已放行，橙 = 本机未放行，红 = 无法连接。「SSH 对全网开放 / 密码登录开启」是主机常态配置，只在第二行灰字提示，不染色——否则全部主机都是橙色，盖住真正要处理的「本机未放行」。
- **没有总览页**：选中主机直接进名单；本机未放行时名单上方出横幅 + 放行按钮，状态出现在问题所在处。
- **同一时刻只有一个强调按钮**：横幅里的「放行本机」是强调样式，工具栏的保持普通样式。
- **「放行本机到全部主机」只对未放行的主机添加**：先强制重探，已放行的跳过，避免名单里堆重复的「本机」条目；各主机实测出口不同时逐台列出。

用户拍板（2026-11-01）：
- 要：启动时探测全部主机（启动会连所有主机一次）、菜单栏图标、出口 IP 变化时通知。
- 不要：「放行本机」时顺手撤销旧「本机」条目。

## SDK 27 用得上的 API

- 标准控件自动适配液态玻璃、系统玻璃透明度滑块、非活动窗口样式。
- `alert` / `confirmationDialog` 的 `item:` 重载：撤销放行、删除转发、忘记主机的确认框。
- 工具栏 `visibilityPriority(_:)`：窄窗口时主操作留在栏上；`ForEach` 可直接放进 `toolbar`。
- `@State` 宏：`@Observable` 视图模型只初始化一次。

写 SDK 27 新 API 前先读 Xcode 自带的 Apple 参考：
`/Applications/Xcode.app/Contents/PlugIns/IDEIntelligenceChat.framework/Versions/A/Resources/swiftui-whats-new-27*`。

## 范围外

- App Intents / 快捷指令：新功能，用户没要，不做。
- iOS 原生：不在本方案内。

## 踩过的坑

- **构建 ffi 时不要设 `MACOSX_DEPLOYMENT_TARGET`**：它也作用于宿主机的过程宏，rustc 1.92 按 27.0 链出的 dylib dyld 加载不了（`mis-aligned LINKEDIT string pool`），表现为 `can't find crate for serde_derive` 一类错误。已经生成的坏产物要 `cargo clean --release -p <宏 crate>` 清掉。
- **Swift Record 不要叫 `Host`**：和 Foundation 的 `Host` 类重名，主机记录叫 `HostInfo`。
- **modulemap 不用 `--xcframework`**：那会生成 `framework module`，而我们打的是静态库 XCFramework；模块名须为 `ipgate_ffiFFI`（生成的 Swift 源码按这个名字 import）。
- **Swift 6.4 编译器在带标签元组的 `compactMap` 推断上会崩**（`failed to produce diagnostic for expression`）：改用小 struct。
- **视图 body 里会写入的缓存（如每主机页面模型字典）标 `@ObservationIgnored`**：否则在视图更新中改了被观察状态。
