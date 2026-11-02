# ADR 0010：macOS 客户端主窗口外壳改用 AppKit，同样的功能 UI 优先用 AppKit

状态：已定案（实施中，进度见 `docs/plans/macos-native-client.md` 第 6 步）
日期：2026-11-01
关联：ADR 0009（本 ADR 取代其决策 2「SwiftUI 为主，AppKit 只用来补局部」）

## 背景

主窗口原来是 SwiftUI 的 `NavigationSplitView`（左栏 + 详情）加 `.inspector`（右栏「访问与安全」）。在 macOS 27 上：

- 左栏开着时展开右栏，动画明显卡顿；窗口不够宽时还会把左栏推出窗口左侧，动画结束再弹回。左栏关着展开右栏也卡。
- 最小 SwiftUI 工程（只有这两样结构、没有业务代码）同样复现，所以不是我们的代码造成的。
- 打印视图树看到：`.inspector` 写在详情页里时，SwiftUI 会在详情栏内部再嵌一层 `NSSplitView`，由 SwiftUI 逐帧驱动。日志显示展开期间中间栏每帧先被压窄、紧接着又被弹回原宽度，两层分栏在抢宽度。
- 左栏的开合是 AppKit 原生动画，一直流畅。
- 用 AppKit `NSSplitViewController`（sidebar / 内容 / inspector 三项）搭的验证工程里，内容仍是 SwiftUI，两个方向开合都不卡、不推（用户实测）。
- 外部也有同类报告：SwiftUI 分栏开合和窗口缩放的卡顿明显多于 AppKit 原生分栏，几个项目最后都改成了 `NSSplitViewController`。

## 决策

| # | 决策 | 理由 |
|---|------|------|
| 1 | **主窗口外壳用 AppKit**：`NSSplitViewController`（左栏 sidebar 项、中间内容项开 `automaticallyAdjustsSafeAreaInsets`、右栏 inspector 项）+ `NSToolbar`（tracking separator 按栏分段）。各栏内容先保留现有 SwiftUI 视图，经 `NSHostingController` 嵌入 | 开合动画交给 AppKit，流畅、不推栏；液态玻璃、浮动侧栏、工具栏分段 AppKit 都能原生拿到 |
| 2 | **同样的功能，macOS 客户端的 UI 优先用 AppKit 写**（用户拍板） | SwiftUI 在 Mac 上的布局和动画问题我们改不了，只能等系统修；AppKit 的行为可控、可调试 |
| 3 | 现有 SwiftUI 页面不为这条规则单独重写；改到某块界面时，按决策 2 评估是否换成 AppKit | 控制改动范围，每步可单独回滚 |

## 备选方案（未采纳）

- **展开前先加宽窗口**（中间栏不够就把窗口拉宽，收起时缩回）：只对左栏方向有效；右栏照样推栏，卡顿也治不了。
- **展开一栏时自动收起另一栏**：改变用户习惯，用户否决。
- **窗口最小宽度加大到约 1130**：窄屏用不了，而且治不了卡顿。
- **不处理**：卡顿和推栏每天都会碰到，用户否决。
- **只把 `.inspector` 挪到 `NavigationSplitView` 外层**：右栏开着时开合左栏好了，但左栏开着展开右栏照样卡、照样推。
- **向 SwiftUI 的右栏发 AppKit `toggleInspector:`**：SwiftUI 的 inspector 不是 `NSSplitViewController` 的分栏项，没有对象接收。

## 影响

- 工具栏不再由各页面的 `.toolbar` 声明，改为外壳统一构建，按钮状态要从模型同步过去。
- ADR 0009 里「以后做 iOS 原生能复用大部分界面」的收益变小；iOS 原生本来就不在当前范围内。
- 页面内容仍是 SwiftUI，Rust 核心与 UniFFI 接口不受影响。
