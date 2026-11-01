# ADR 0009：macOS 客户端改用 SwiftUI 原生

状态：已定案（实施中，进度见 `docs/plans/macos-native-client.md`）
日期：2026-11-01
关联：ADR 0001（客户端技术栈 Tauri 2，本 ADR 只在 macOS 上取代它）、0007（传输：SSH + Noise）

## 背景

Tauri 版在 macOS 上是 WKWebView + 自绘 CSS。窗口用的是 Overlay 标题栏，侧栏和顶栏都是 Web 画的，系统的液态玻璃材质、工具栏、侧栏样式都套不上；滚动、转场、手势的手感也和原生有差距。升级 Xcode / SDK 对 WebView 内容没有任何影响。

## 决策

| # | 决策 | 理由 |
|---|------|------|
| 1 | **macOS 客户端用 SwiftUI 重写 UI**；iOS / Android / Windows / Linux 继续用 Tauri | 液态玻璃、侧栏、工具栏、菜单只有标准控件能自动拿到，Web 只能用 `backdrop-filter` 模仿毛玻璃。其余平台暂不改，避免一次性维护面翻倍 |
| 2 | **SwiftUI 为主，AppKit 只用来补局部**（`NSViewRepresentable`） | 新系统的设计最先落在 SwiftUI；标准控件自动适配液态玻璃、玻璃透明度滑块、非活动窗口样式；以后要做 iOS 原生也能复用大部分界面 |
| 3 | **Rust 核心抽成独立 crate `ipgate-client-core`**（`client/core/`，不依赖 Tauri），Tauri 和 SwiftUI 共用 | 传输、Noise、身份、密钥存储都是安全攸关逻辑，只能有一份实现。Tauri 的 `commands.rs` 退化成薄包装 |
| 4 | **Swift 通过 UniFFI 调 Rust**（`client/ffi/`，打包成 XCFramework），接口类型化，异步方法映射为 Swift `async` | 类型由 Rust 生成，Swift 侧不会和 Rust 结构体漂移（延续 ADR 0001「单一可信源」）；比手写 C ABI + JSON 少一层易错的胶水 |
| 5 | **最低系统版本 macOS 27**（用户拍板） | 主要用户就在 27 上；新 API（工具栏 `visibilityPriority`、`alert(item:)` 等）直接用，不写 `if #available` 兜底 |
| 6 | **新 Bundle ID `com.ipgate.mac`，和 Tauri 版并存**；Keychain service、数据目录都用新的（用户拍板） | 不碰 Tauri 版的数据。设备身份和主机清单用现有的「导出 / 导入身份」功能迁移，不写迁移代码 |
| 7 | 开启 App Sandbox（仅 `network.client` + Keychain） | 客户端只发起出站连接，沙盒成本低，私钥面更小 |

## 备选方案（未采纳）

- **继续用 Tauri，Web 侧模仿 iOS / macOS 风格**：成本最低，但做不出真正的液态玻璃，手感差距补不上。
- **纯 AppKit**：只能用在 Mac 上，新设计跟进慢，写法啰嗦，对 ipgate 这种规模的界面没有收益。
- **Swift 侧重写传输 / Noise**：安全逻辑出现两份实现，否决。

## 影响

- 每个新功能在 macOS 上要写两遍 UI（SwiftUI + Tauri Web）；Rust 核心只写一遍。
- Tauri 版的 macOS 构建暂时保留，原生版功能补齐后再决定是否停发（待用户决定）。
- 客户端私有仓库（`client/`，不进本公开仓库）新增 `core/`、`ffi/`、`mac/` 三个目录，各自是独立 Cargo workspace / Xcode 工程，不并入根 workspace。
