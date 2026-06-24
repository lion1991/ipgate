# client

跨端 GUI 客户端:一套 **Tauri 2** 代码产出 macOS / Windows / Linux / **iOS**(Android 待接入)。

所有变更经 agent 完成,客户端**不直接操作内核**。安全攸关逻辑(TLS、密钥、令牌)全在
**Rust 侧**;前端只通过 `invoke` 调用命令,绝不直连网络、不接触私钥(ADR 0003 的前提)。

## 选型

| 维度 | 选择 |
|------|------|
| 框架 | Tauri 2(Rust 核心 + WebView 前端) |
| 前端 | **vanilla TypeScript + Vite**(最轻、零框架锁定;Rust 核心与前端解耦,日后可换 Vue/React) |
| 传输 | `reqwest`(rustls 后端,**仅 TLS 1.3**)+ 自定义 SPKI 指纹固定校验器 |
| 设备密钥 | `ed25519-dalek`,种子用 OS CSPRNG 生成;私钥**永不离开设备** |
| 协议类型 | 直接依赖同仓库 `proto/` crate —— 线格式与 agent 单一可信源 |

## 架构(`src-tauri/src/`)

| 文件 | 职责 |
|------|------|
| `crypto.rs` | 设备 Ed25519 密钥;`pair_message` / `auth_message` 待签字节(与 agent 逐字节一致);SPKI 指纹计算 |
| `tls.rs` | TOFU 指纹固定的 `ServerCertVerifier` + reqwest 客户端构建(TLS 1.3) |
| `api.rs` | agent REST 调用(用 proto 类型) |
| `store.rs` | 本地持久化:设备身份 + 已配对主机(known-hosts),JSON @ app data 目录(0600) |
| `commands.rs` | 暴露给前端的 Tauri 命令 + 会话令牌缓存/重登 |
| `lib.rs` | 应用装配 + 共享状态 |

前端在 `index.html` / `src/`(`api.ts` 命令包装、`main.ts` 逻辑、`styles.css`)。

## 安全模型要点

- **TOFU**:首连(`probe_host`)不固定证书,取回服务端 SPKI 指纹(`SHA-256` 冒号大写),
  用户与 agent 上 `ipgate-agent pair` 打印值**带外核对**后才固定;此后指纹不符 → 硬失败(MITM 告警)。
- **配对**:提交 `{设备公钥, 设备名, 对配对码的签名}`,agent 验签 + 消费一次性配对码。
- **登录**:每会话挑战-应答(`nonce ‖ 服务端指纹` 签名)换取短时 Bearer 令牌(默认 15 min,内存缓存,遇 401 自动重登)。
- 该 workspace **独立**于根 workspace(空 `[workspace]`),以免 agent 的 `cargo test --workspace`
  在 Linux CI 上被迫编译 GUI 依赖。`proto` 经 path 依赖跨界引用。

## 开发

```sh
pnpm install
pnpm tauri dev      # 桌面调试(热重载)
pnpm tauri build    # 打包当前平台

# Rust 侧单测(纯逻辑:待签消息、指纹格式、目标解析)
cd src-tauri && cargo test
```

移动端(iOS,脚手架在 `src-tauri/gen/apple/`):

```sh
pnpm tauri ios dev "iPhone 17"   # 起模拟器调试(首次为 iOS target 编译 Rust 核心,较慢)
pnpm tauri ios build             # 打包 .ipa(需配置签名)
```

UI 已做窄屏适配:`max-width: 640px` 切单栏 + **底部 Dock 导航**(主机/名单/设备/同步,
常驻;点分区直接进当前主机对应页,点「主机」回列表)。数据列表为 iOS 风分组列表(Tailscale
风):主机/设备带字母头像、设备有在线点 + 「本机」标识、名单条目配到期胶囊;输入框 ≥16px 防
iOS 聚焦缩放、`env(safe-area-inset-*)` 适配刘海/底部 home 条。设计稿见 `designs/mobile-redesign/`。
Android 端日后
`pnpm tauri android init` 即可(Rust target 已就绪,需 `NDK_HOME`)。

## 待办

- [x] 桌面骨架 + Rust 核心(TLS 固定 / 配对 / 登录 / 名单增删 / 设备 / 同步)
- [x] 主机管理 + 配对向导 UI
- [x] iOS 脚手架(`tauri ios init`)+ 响应式移动 UI,模拟器跑通
- [ ] 移动端密钥改存 Keychain / Keystore(现为 app data JSON)
- [ ] Android 接入(`tauri android init`)
- [ ] 实时同步(WebSocket,待 agent 侧加)
- [ ] 签名 happy-path 的真实端到端联调(对真机 agent)
