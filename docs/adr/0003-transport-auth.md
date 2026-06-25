# ADR 0003：传输与鉴权

状态：已定案
日期：2026-06-23
关联：ADR 0001（整体架构）、ADR 0002（nftables 落地方式，待定）

## 背景

agent 持有 `CAP_NET_ADMIN`，是唯一能改 nftables 的组件。谁能通过它的 API 鉴权，谁就能放行任意 IP、绕过这台主机的防火墙。所以传输与鉴权是整个项目的安全基石。

约束：
- 客户端要覆盖移动端 / PC / Mac，需从任意网络直连**主机 (Host)** 上的 agent。
- VPS 常按 IP 管、无域名，签不到公共 CA 证书。
- **鸡生蛋**：本工具管的就是 IP 放行名单。若 agent 自己的管理端口也被它管的名单挡住，移动端换个出口 IP 就再也连不进来。

## 决策

| 维度 | 选择 |
|------|------|
| 传输 | **REST / JSON over rustls（TLS 1.3）**，默认端口 `19186`（可配） |
| 服务端身份 | **TOFU 指纹固定**（agent 自签证书，客户端首连记 SPKI 指纹，像 SSH known_hosts） |
| 客户端鉴权 | **每设备 Ed25519 密钥 + 一次性配对码**；agent 维护 `authorized_keys`，按设备可吊销 |
| 会话 | 挑战-应答证明持有私钥 → 换取短时 **Bearer 会话令牌**（默认 15 min） |
| 暴露模型 | 公网直连，管理端口**永不进受管名单**，靠 TLS + 密钥鉴权 + 限速/锁定扛 |

> Tauri 的网络请求在 **Rust 侧**（reqwest/rustls）发出，不经 WebView，因此自定义证书校验、Ed25519、TLS 1.3 全部可用——这是上述选型成立的前提。

## 详细设计

### 1. 传输

- 仅 **TLS 1.3**（rustls），禁用更低版本与弱套件。
- **REST / JSON**：放行/撤销是低频操作，REST 可读可调试、两端实现轻。
- 实时同步 / 审计流后续按需加 WebSocket（升级自同一 TLS 端口），不在本 ADR 范围。
- 服务端 `axum` + `tokio-rustls`；客户端 `reqwest`（rustls 后端）+ 自定义 `ServerCertVerifier`。

### 2. 服务端身份：TOFU 指纹固定

- agent 首次启动生成长期**自签证书**（Ed25519 密钥，`rcgen`）。
- 固定对象是 **SPKI 的 SHA-256 指纹**（不是整张证书）——这样证书到期续签、只要密钥不变，客户端无需重新固定。
- 安装时 agent 在控制台**打印指纹**，供带外核对。
- 客户端首连：展示指纹（理想情况下与配对码一同带外核对，见下），用户确认后按 `host:port` 存入本地 known-hosts。
- 后续连接指纹不符 → **硬失败 + MITM 告警**，不静默接受。

### 3. 客户端鉴权：每设备 Ed25519 + 配对码

**密钥**：每台设备首次运行生成一对 Ed25519 密钥（种子 32 字节）。私钥**永不离开设备**，存于安全存储：
- **Apple（iOS / macOS）：Keychain（已实现）** —— `keyring` crate；首启把旧版明文 JSON 种子**安全迁移**进 Keychain（先写入、确认成功后才从 JSON 抹去），iOS 模拟器已验证读/写/迁移。
- Android：Keystore（待接入）；桌面 Windows/Linux：系统密钥库（待接入）。当前这两类暂用 app data 下 **0600 单独文件**兜底（已与主 JSON 分离）。

**入网（配对，一次性）**：
```
管理员在主机执行： ipgate-agent pair
  └─ agent 打印： 配对码(短、单次、~10min 过期) + 服务端指纹
用户在客户端输入： 主机地址 + 配对码
  └─ 客户端 TOFU 固定指纹(与打印值核对) → 提交 {设备公钥, 设备名, 对配对码挑战的签名}
agent 校验配对码 → 把公钥写入 authorized_keys(附设备名/时间) → 配对码作废
```

**登录（每会话，挑战-应答）**：
```
POST /v1/auth/challenge {device_id}        → agent 返回 {nonce, expires}
客户端用设备私钥签名： nonce ‖ timestamp ‖ 服务端SPKI指纹   (绑定信道，防重放到别处)
POST /v1/auth/verify {device_id, signature} → agent 验签(对 authorized_keys) → 发 {token, expires}
后续请求携带： Authorization: Bearer <token>
```
- nonce 单次、短时；签名绑定服务端指纹，截获的挑战无法重放到另一端点。
- 会话令牌：不透明字符串 + agent 侧 HMAC 密钥签发（或 PASETO v4），**不用 JWT**（避免 alg 混淆等坑）。TTL 短，配合刷新。

**吊销**：`authorized_keys` 即控制面，移除某设备公钥即吊销；令牌短 TTL 兜住窗口期，另设 token epoch 可即时全量失效。

### 4. 加硬（公网直连的代价要补回来）

- **访问密钥门（已实现，v0.1.7）**：管理端口虽对全世界开（防自锁不变量），但每个请求须带
  `X-Ipgate-Key: <访问密钥>`，否则**一律裸 404**（不回 401、不回 JSON 错误）——扫描器看到的就是
  个「死端口」，识别不出 ipgate，连 `/healthz`、`/v1/pair` 都变暗。门是**路由前**的中间件，无密钥者
  连配对/挑战/JSON 解析的代码都碰不到，把「整套鉴权栈裸露公网」收成「持密钥者才能触碰」，挡未知
  实现 0-day 与探测。密钥 = 128-bit、`data_dir/access.key`(0600)、`ipgate-agent access-key[ --reset]`
  打印/轮换；配对时随 `ipgate-agent pair` 的 **join 串**（`访问密钥.配对码`）一次性带给客户端，之后
  客户端每次请求自动带。常数时间比较。`require_access_key` 默认 **false**（升级既有部署不破现有客户端），
  全新安装由 install.sh 置 true。**它只挡 19186 的 HTTP**——本地 CLI / SSH(22) 都不经此门，绝不新增自锁路径。
- **预鉴权端点最小化**：仅 `/v1/auth/challenge`、`/v1/auth/verify`、`/v1/pair`、`/healthz`。其余一律需 Bearer。
- **限速（已实现）**：按源 IP 固定窗口限速（默认 120 次/分，`rate_limit_per_min`，超额 429），挡探测/刷量/暴力。
  `auth/verify` 连续失败 N 次锁定该源（fail2ban 式）、全局并发上限**后续可加**。
- **超时**：读/写/空闲超时，防 slow-loris（reqwest/axum 侧默认 + 连接超时）。
- 防御纵深（**后续可选**）：mTLS 双向证书（用设备 Ed25519 派生客户端证书，TLS 握手层拒匿名连接）；
  SPA / 端口敲门隐藏端口；WireGuard 模式。

### 5. 不变量：别把自己锁在门外（鸡生蛋的解）

> agent 安装的 nftables ruleset，**必须在受管名单 drop 之前，无条件 `accept` 管理端口**，无论放行名单内容如何。

- 管理端口（默认 19186）**永不**作为受管名单的一员；它是常开的、靠鉴权保护的带外通道。
- agent 必须**拒绝**任何会挡住自身管理端口的操作。
- 具体 ruleset 布局（accept 管理端口 → `ip saddr @ipgate_allow accept` → drop）在 ADR 0002 落地时固化。

## API 草图（细节随 proto 定稿）

```
POST   /v1/auth/challenge     取 nonce
POST   /v1/auth/verify        验签换令牌
POST   /v1/pair               配对入网(窗口期内)
GET    /v1/allowlist          列出条目
POST   /v1/allowlist          放行(Allow)   {target, note, expires_at?}
DELETE /v1/allowlist/{id}     撤销(Revoke)
POST   /v1/sync               同步差异
GET    /v1/devices            已授权设备
DELETE /v1/devices/{id}       吊销设备
GET    /v1/audit              审计日志
GET    /healthz               存活探针(预鉴权)
```

## 选型（crate）

| 用途 | crate |
|------|-------|
| TLS | `rustls` + `tokio-rustls` |
| 服务端 HTTP | `axum`（基于 hyper） |
| 客户端 HTTP | `reqwest`（rustls 后端，自定义 cert verifier） |
| 自签证书生成 | `rcgen`（Ed25519） |
| 签名/验签 | `ed25519-dalek` |
| 随机/nonce | `getrandom` / `rand` |
| 令牌 | 不透明 + HMAC（`hmac`+`sha2`）或 PASETO v4 |
| 移动端密钥存储 | 平台 Keychain/Keystore 插件 或 `tauri-plugin-stronghold` |

## 威胁与对策

| 威胁 | 对策 |
|------|------|
| 公网端口被扫/爆破 | **访问密钥门**：无密钥一律 404，端口对外「变暗」、扫不出 ipgate；纯密钥鉴权(无口令可爆)、per-IP 限速、预鉴权面最小 |
| 伪造客户端下命令 | 受管操作须 Bearer 令牌：要么 HMAC 伪造(需服务端 secret=已 root)、要么 Ed25519 挑战-应答(需设备私钥)、要么配对(需活的一次性配对码)——三者皆网络不可得 |
| 中间人 | TLS 1.3 + TOFU 指纹固定；指纹变更硬失败 |
| 重放签名 | nonce 单次短时 + 挑战绑定服务端指纹 |
| 客户端/设备失窃(偷钥匙=伪造客户端) | 私钥存安全区(Apple=Keychain 已实现,不可导出);按设备吊销;令牌短 TTL |
| 把自己锁在门外 | 管理端口永在名单之外且 ruleset 优先 accept;agent 拒绝自锁操作 |
| 令牌泄露 | 短 TTL + token epoch 即时失效 |

## 影响 / 后续

- **安全边界**：客户端被攻破，最多拿到该设备的会话能力(改防火墙),且可在 agent 侧按设备吊销;不波及 shell/root。
- **驱动 proto**：`AuthChallenge`/`AuthVerify`/`Pair`/`SessionToken`/`Device` 等类型进入 `proto/`。
- **驱动 ADR 0002**：nft ruleset 必须落地"管理端口优先 accept"的不变量。
- **驱动 ADR 0004（部署）**：`ipgate-agent pair` 子命令、首启生成证书并打印指纹、systemd 暴露 19186。
- 桌面端 known-hosts/私钥存储路径、移动端 Keychain 集成为后续实现细节。
