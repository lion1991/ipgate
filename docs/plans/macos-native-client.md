# macOS 原生客户端（SwiftUI）实施方案

状态：第 1–7 步完成，功能与 Tauri 桌面版对齐，主窗口外壳已改 AppKit，待用户日常试用
日期：2026-11-01
关联：ADR 0009（定案）、0010（外壳改 AppKit）、0007（传输）

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
   - **4b 名单表格**：✅ 覆盖当前出口的条目标「当前」、列排序（默认保持 agent 顺序）、「添加时间」列（悬停看添加者）、多选批量撤销（一次确认）、「+」改为锚定弹出框。
   - **4c 菜单栏图标 + 出口 IP 变化通知**：✅ 菜单栏窗口式面板（各主机状态、刷新、面板内两步确认的「放行本机到全部主机」、点主机打开主窗口）；主窗口改为单个 `Window`，关窗后留在菜单栏。网络切换（路径签名变化且可用）或唤醒后防抖 3 秒：core `reset_connections` 丢弃旧连接 → 强制重探全部主机 → 出口变了且有主机未放行才发通知（首次需要时申请权限，点通知打开主窗口）。
5. **补齐其余页面**：端口转发、安全设置、设备、配对、同步、身份导出/二维码；工具栏分段控件切换分区。同步（对账）、改名等低频主机操作放侧栏右键与「主机」菜单。
   - **5a 分区切换 + 安全**：✅ 工具栏分段控件（放行名单 / 端口转发 / 安全 / 设备，⌘1–⌘4，切主机保持分区）；「安全」分区为分组表单：SSH 仅名单可连、允许密码登录、重置 root 密码、转发名单门。确认文案与收紧 SSH 前的自锁核对沿用 Tauri 版。
   - **5b 端口转发**：✅ 进分区才加载；统一表格（native + dnat，dnat/冲突标签、备注与解析结果）；右键编辑/迁移/拷贝/删除，双击编辑（dnat 为迁移），Delete 键批量删除；添加/编辑共用表单（协议分段、网卡下拉，旧 agent 退回文本框）；列表上方显示转发名单门状态，「设置…」跳安全分区。
   - **5c 设备 + 主机管理**：✅ 「设备」分区（进分区重拉；本机标签、在线状态、吊销，吊销本机强警告）；侧栏右键与「主机」菜单共用主机管理：重命名、设置访问密钥、更新 Noise 公钥（可粘配对链接，先实握手校验）、对账（只读表单）、移除主机。
   - **5d 配对新主机**：✅ 侧栏「+」、文件菜单「添加主机…」⌘N、无主机时的空状态都能进；粘贴配对链接后同一表单内展开主机信息、显示名、本设备名，配对成功选中新主机并探测。
   - **5e 身份导出 / 二维码**：✅ 文件菜单「导出设备身份…」（无主机时不可用）；口令输两次，生成后显示白底黑码的多帧轮播二维码（0.9 秒一帧，与 Tauri 版同节奏）和文本备份，「拷贝备份」在底栏。macOS 只出码不扫码，扫码导入在手机端。
6. **主窗口外壳改 AppKit**（ADR 0010）：✅ `NavigationSplitView` + `.inspector` 换成 `NSSplitViewController`（左栏 / 内容 / 右栏）+ `NSToolbar`（按栏分段）；各栏内容仍是现有 SwiftUI 视图。原因：SwiftUI 驱动的右栏展开卡顿，左栏开着时还会把左栏推出窗口。先用验证工程实测开合流畅、不推栏，外观对齐后再迁移。外壳在 `mac/ipgate/MainWindow.swift`：工具栏按钮统一在这里构建，状态用 `withObservationTracking` 从模型同步，页面里不再写 `.toolbar`；「放行」弹出框是锚在工具栏按钮上的 `NSPopover`；侧栏搜索是原生 `NSSearchField`。

7. **主机出口 IP + 公开端口**（ADR 0011，需 agent ≥ 0.2.10）：✅ 右栏「访问与安全」加「主机出口」（IPv4 / IPv6，可选中、右键拷贝；打开右栏时才探测，⌘R 重探）；新增「公开端口」分区（⌘5，追加在末尾不打乱 ⌘1–⌘4）：表格列端口 / 协议 / 备注，config.json 里的标「配置文件」只读；右键编辑备注 / 拷贝 / 删除，双击编辑，Delete 键批量删除，工具栏「+」添加。旧 agent 显示升级提示。

## 界面设计决策

按使用频率设计：最常见的是「出口 IP 变了进不去 → 放行本机」，其次是清理名单，转发/安全/设备/配对/同步是偶尔操作。

- **侧栏图标只回答「我进得去吗」**：绿 = 已放行，橙 = 本机未放行，红 = 无法连接。「SSH 对全网开放 / 密码登录开启」是主机常态配置，只在第二行灰字提示，不染色——否则全部主机都是橙色，盖住真正要处理的「本机未放行」。
- **没有总览页**：选中主机直接进名单；本机未放行时名单上方出横幅 + 放行按钮，状态出现在问题所在处。
- **同一时刻只有一个强调按钮**：横幅里的「放行本机」是强调样式，工具栏的保持普通样式。
- **撤销确认只在真会自锁时警告**：本地判断撤销后当前出口是否仍被剩余条目覆盖，不再覆盖才提示，并按 SSH 暴露方式措辞（仅名单 → 自锁警告；全网开放 → 说明不影响管理连接）；只信主机实测的出口（外部探测可能走代理/双栈，与 sshd 看到的不同），出口未知或来自外部探测时一律用保守的通用警告；已过期未清理的条目不算覆盖（内核里已不生效）。
- **安全设置用开关，但开关不直接改值**：点击先出确认，确认下发、agent 返回新设置后开关才变；收紧 SSH 前强制重探出口，不在名单或无法确认时用危险措辞。「密码登录开启」按 PasswordAuthentication 或 KbdInteractive 任一开着算（与 Tauri 版一致）。重置 root 密码输两次，防手误连控制台都登不上。
- **配对只要粘一条链接**：链接已含公钥、隧道凭据和配对口令，不再让用户核对指纹或手输口令；解析成功就在同一表单展开确认信息，不分两步。本设备名默认取 Mac 的电脑名，方便在服务器设备列表里认出；已有同地址主机时提示（不拦截，agent 重装后重新配对是正常用法）。macOS 不做扫码，与 Tauri 桌面端一致。
- **「放行本机到全部主机」只对未放行的主机添加**：先强制重探，已放行的跳过，避免名单里堆重复的「本机」条目；各主机实测出口不同时逐台列出。

用户拍板（2026-11-01）：
- 要：启动时探测全部主机（启动会连所有主机一次）、菜单栏图标、出口 IP 变化时通知。
- 不要：「放行本机」时顺手撤销旧「本机」条目。

用户拍板（2026-11-05）：
- 要：主机出口 IP（服务器自己往外连的公网地址，agent 用成熟的公共检测服务探测）；按端口对全部 IP 放行（「公开端口」独立分区，每条带备注）。
- SSH「仅名单可连」时不许把 SSH 端口加成公开端口，提示去「安全」改。
- 默认窗口 1037×693、侧栏 220、右栏 240（即用户当时的布局），居中的分区控件刚好不越过右栏分隔线。
- 不要：工具栏按栏分段（`NSTrackingSeparatorToolbarItem` 把右栏开关隔到右栏上方）。NSToolbar 不把分隔线当硬边界，中间栏放不下标题 + 分区控件 + 放行本机 / + / 刷新时照样越线，反而更难看。

## SDK 27 用得上的 API

- 标准控件自动适配液态玻璃、系统玻璃透明度滑块、非活动窗口样式。
- `alert` / `confirmationDialog` 的 `item:` 重载：撤销放行、删除转发、忘记主机的确认框。
- 工具栏 `visibilityPriority`（AppKit `NSToolbarItem`）：窄窗口时主操作留在栏上。
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
- **Rust 构建放在聚合 target `RustCore`，不要放 app 的 preBuildScript**：Xcode 在 app target 的脚本阶段之前就把 XCFramework 头文件拷进构建目录，ffi 一改，第一次构建会用旧头文件报找不到符号。
- **网络切换后先 `reset_connections` 再重探**：旧连接可能要等 30 秒 RPC 超时才发现断了；没断的话主机实测到的仍是旧出口。
- **视图 body 里会写入的缓存（如每主机页面模型字典）标 `@ObservationIgnored`**：否则在视图更新中改了被观察状态。
- **工具栏分段控件要 `visibilityPriority = .high`，并设为 `centeredItemIdentifiers`，窗口最小宽 860；默认栏宽一改，分区控件可能越过右栏分隔线，改前截图核对**：否则窗口一窄，分区切换会被折成下拉或挤进「»」；不固定居中的话右侧按钮随分区增减，它会左右挪。「放行本机」优先级 `.low` 先让位（名单上方横幅里也有）。
- **分区控件自己建 `NSSegmentedControl`（`segmentDistribution = .fit`，每段按标题自适应），不用 `NSToolbarItemGroup(titles:)`**：后者生成的控件等宽且比外层玻璃胶囊宽，最后一段的长标题（「公开端口」）会越出胶囊；按最长标题等宽也不行，整条过宽会贴到右侧按钮。收进溢出菜单靠 `menuFormRepresentation` 的子菜单。
- **自定义 view 的工具栏项也要给 item 设 target / action**：收进溢出菜单时菜单项用的是 item 自己的，只设在按钮上会点不动。
- **`NSSearchField` 点 × 清空、按 Esc 不发 `controlTextDidChange`**：要同时接 target / action，否则过滤停在旧关键字。
- **整页加载用 `LoadingView`（0.3 秒后才显示转圈）**：数据通常百毫秒内回来，直接出 `ProgressView` 会一闪而过。
- **SwiftUI 的 `NavigationSplitView` + `.inspector` 开合会卡、会推栏，改不掉**：左栏开着展开右栏，中间栏动画期间不缩，整体被推出窗口左侧、结束再弹回；最小工程也复现。拆分工具栏项、改最小宽度、加宽窗口、把 `.inspector` 挪到外层都治不了，最后换成 AppKit 外壳（ADR 0010）。排查时注意：给侧栏挂 `onGeometryChange` 会让问题消失，验证要用不改布局的手段（系统日志 + 用户实测）；菜单里的「显示检查器」不走动画，不能拿来测。
