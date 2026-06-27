# ADR 0007：传输改用 Noise，强制经 SSH 载体（取代 0003 传输层）

状态：已定案并落地——**agent 端已完整实现**（Phase 0/1a/1b/1c/3，proto+agent 81 测试绿，含真 TCP+Noise 端到端）；客户端（Phase 2）+ 移动端（Phase 4）待做。
日期：2026-06-26
关联：**取代 [ADR 0003](0003-transport-auth.md) 的「传输 / 服务端身份 / 会话」三项决策**；沿用其「设备身份」「吊销」「不自锁」思路；关联 ADR 0001、ADR 0002（nft 不变量）

## 背景

ADR 0003 把管理面定为 **REST/JSON over rustls(TLS 1.3) + TOFU 指纹固定 + Bearer 令牌**，管理端口公网直连。该方案安全性达标，但**暴露/检测面**是短板：

- TLS 握手 ClientHello 明文可辨；rustls 的 JA3/JA4 指纹「非浏览器」，在流量里扎眼。
- 默认 `19186` 非标准端口上的 TLS，本身是被动 DPI 的高权重信号。
- agent 是个**公网监听的服务**——「面板 / 探针」类特征的根源：有端口可扫、有服务在听。

目标环境约束（本 ADR 的触发点）：**某些网络禁止 / 主动识别一切「管理面板、监控探针、TLS 服务」**。在这种约束下，「把 TLS 打扮得更像网站」只能治标（指纹、主动探测、端口扫描仍在）；必须**换形状**——线上不出现 TLS、不出现可发现的监听服务。

候选方案评估（详见对话记录）：SSH 隧道、WireGuard、Noise、自加密 over HTTP/80、SPA 单包授权、出站汇合。结论取**两层合成**。

## 决策

**Noise 当协议（端到端鉴权 + 加密），SSH 当强制载体（伪装 + 信道）。** agent 对外**零开放端口**，只在 `127.0.0.1` 上听 Noise；唯一入口是 SSH 隧道，线上看到的永远是一条 SSH 会话。

| 维度 | 0003（旧） | 0007（新） |
|------|-----------|-----------|
| 线上协议 | TLS 1.3 (REST/JSON) | **SSH**（隧道），内层 Noise（不透明字节） |
| 监听暴露 | 公网 `19186` | **仅 loopback**，对外无端口 |
| 信道加密 | rustls TLS 1.3 | SSH（外）+ Noise（内），双层 |
| 服务端身份 | TLS SPKI 指纹（TOFU 固定） | **Noise 静态公钥**（TOFU 固定，QR 带） |
| 设备鉴权 | Ed25519 配对 + 挑战-应答 + Bearer 令牌 | **Noise_IK 握手一次完成**（详见下） |
| 会话令牌 | 短时 Bearer（HMAC） | **删除**（每条 Noise 会话自带双向认证 + 前向保密） |
| 自锁不变量 | 管理端口 `19186` 永在名单外 | **SSH 端口**永在名单外（loopback 口天然免规则） |

### 为什么两层都要（不是冗余）

- **SSH**：在 VPS 上是最天经地义、最不可能被禁的**非-TLS** 协议——提供伪装（合法协议）、信道加密、转发管道。
- **Noise**：提供**端到端、per-device 身份**——扫码配对、按设备授权 / 吊销，**与 SSH 账户解耦**。SSH 只认「能登机器的账户」；我们不想给每台手机塞一把能登 VPS 的私钥，更不想「有 SSH = 全权控制 agent」。手机丢了在 app 里吊销那台设备即可，不动 VPS 的 `authorized_keys`。

## 详细设计

### 1. 协议选型：`Noise_IK`（snow crate）

`Noise_IK` 语义与 ipgate 严丝合缝，**一次握手吃掉旧设计的三样东西**：

| 0003 机制 | Noise_IK 对应 | 效果 |
|-----------|--------------|------|
| TLS 指纹固定（认服务器） | **I**nitiator 预先 **K**nows responder 静态公钥 | 客户端预置 agent 静态公钥 = 指纹固定，QR 照带 |
| Ed25519 配对（认设备） | 握手中 initiator 静态公钥（加密）发给 responder | agent 查「这把静态公钥在不在授权列表」= 配对 |
| 挑战-应答换 Bearer 令牌 | 每条 Noise 会话天生双向认证 + 前向保密 | **令牌机制整套删除** |

- 套件：**`Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s`**（`proto::NOISE_PATTERN`）；psk0 见「已决 §3」。
- 静态密钥：**X25519**（Noise 的 DH 类型）。
- 传输分帧：裸 TCP（实为 SSH 转发的 loopback 流）上 `u16 大端长度前缀 ‖ Noise 密文`；单帧 ≤ 65535 字节。

### 2. 物理布局（载体 = SSH 本地转发）

```
客户端（桌面/CLI/移动）                       VPS
┌────────────────────┐   SSH(22) 隧道       ┌──────────────────────────┐
│ russh: ssh -L       │ ==================>  │ sshd（受限 key：仅转发）   │
│   →127.0.0.1:NPORT  │  线上 = 纯 SSH 流量  │   └ forward → 127.0.0.1:N  │
│ snow: Noise_IK ─────┼─── 端到端鉴权/加密 ──┼──→ agent（仅听 loopback:N）│
│   → JSON-RPC        │                     │     对外零开放端口         │
└────────────────────┘                     └──────────────────────────┘
```

- **agent**：`bind` 普通 TCP 于 `127.0.0.1:NPORT`（不再 `bind_rustls`，不再公网监听）；每连接先 Noise_IK 握手，校验对端静态公钥 ∈ 授权列表，再进入请求循环。
- **客户端**：`russh`（纯 Rust SSH）在 app 内建本地转发 → `snow` 在转发流上跑 Noise_IK → 应用层 JSON-RPC。三层全在 Tauri 的 **Rust 侧**，iOS/Android/桌面同源，**无原生依赖**。
- **SSH 凭据**：转发限定的**受限 key**——`authorized_keys` 中 `restrict,permitopen="127.0.0.1:NPORT",command=""`（no-pty、no-shell、只许转发到 Noise 口）。该 key 即便泄露，也只换来「能触达 Noise 端口」，仍须 Noise 设备鉴权才能下任何命令，故可单把共享或随配对下发。

### 3. 配对（一次性，QR 升级到 v2）

```
管理员在主机： ipgate-agent pair --qr --host <地址>
  └─ 打印： agent Noise 静态公钥(X25519) + 配对码(单次,~10min) + SSH 端口 + 受限转发 key
     QR JSON v2： {v:2, h:host, ssh:22, nk:<noise静态公钥 b64>, c:<配对码/join>, sk:<受限key或获取方式>}
客户端扫码： TOFU 固定 nk → 建 SSH 隧道 → Noise_IK 握手(本端临时静态公钥随握手送达)
  └─ agent 校验配对码 → 把客户端静态公钥写入授权列表(附设备名/时间) → 配对码作废
```

- 配对码仍：16 hex、单次、~10min TTL、磁盘只存哈希（沿用 0003 / 现实现）。
- 指纹核对从「SPKI 指纹」改为「Noise 静态公钥」，经 QR 屏幕可信通道直接固定，免手抄。

### 4. 应用层：极简 JSON-RPC（取代 REST/HTTP）

Noise 层夹在 TCP 与应用之间，使 reqwest/axum「跑在流上」很别扭；且本 ADR 目标之一是**线上无 HTTP 行为**。故内层改为请求/响应式 JSON-RPC：每条 Noise transport 消息 = 一个 `{op, body}` → 一个 `{ok|err, data}`。

- `op` 覆盖现有路由语义：`allowlist.{list,add,remove}`、`whoami`、`sync`、`forwards.{list,add,remove,dnat_remove,dnat_migrate}`、`interfaces`、`devices.{list,revoke}`、`pair`。
- 删除 agent 侧 `axum`/`axum-server`、客户端 `reqwest`/`hyper` 依赖；业务逻辑（nft 落地 / dnat / 限速）不变，仅换调用入口（dispatcher 取代 handlers 的 HTTP 提取器）。

### 5. 可退役 / 简化的旧机制

- **访问密钥门（X-Ipgate-Key 裸 404）**：其存在意义是「公网 HTTP 端口对扫描器变暗」。loopback-only 后无公网端口可扫，**该门作为 HTTP 中间件退役**——但那把 128-bit access key **转生为 Noise 的 PSK**（psk0），继续提供「无密钥连握手都完不成，字节全随机、无固定头」的不可探测性（见「已决 §3」）。
- **会话令牌 / 挑战-应答 / HMAC secret**：删除（见 §1）。
- **自锁不变量**：从「管理端口 19186 优先 accept」**转移**为「**SSH 端口优先 accept**」。loopback 上的 Noise 口天然不经 nftables（本机回环），无需放行规则；真正必须守住的是 SSH(22) 不被受管名单挡住——这本就是管理员命脉，反而更简单、更难自锁。

## 选型（crate）

| 用途 | 旧（0003） | 新（0007） |
|------|-----------|-----------|
| 线上传输 | rustls + tokio-rustls | **russh**（SSH 载体，含移动端） |
| 端到端协议 | —（靠 TLS） | **snow**（Noise_IK） |
| 服务端 HTTP | axum / axum-server | **删除**（JSON-RPC dispatcher） |
| 客户端 HTTP | reqwest | **删除**（snow 流上直接收发） |
| 自签证书 | rcgen | **删除** |
| 签名/AEAD | ed25519-dalek / —— | X25519 + ChaChaPoly（snow 内置）；ed25519-dalek 仅留给身份导出 |

## 威胁与对策（相对 0003 的变化）

| 威胁 | 0007 对策 |
|------|-----------|
| **被识别在跑 TLS / 面板 / 探针** | 全链路零 TLS、零 HTTP 行为、零开放端口；线上仅 SSH(VPS 标配)。**本 ADR 的核心目标** |
| 公网端口被扫/爆破 | 无公网端口；探 VPS 只见 sshd；Noise 端点在 loopback，无 SSH 会话够不着 |
| 中间人 | SSH 主机密钥 known_hosts + Noise 静态公钥 TOFU 固定（双层），任一不符硬失败 |
| 伪造客户端下命令 | Noise_IK 双向认证：须持已授权的 X25519 设备私钥；SSH 受限 key 仅给「到达权」不给「控制权」 |
| 重放 / 前向保密 | Noise 每会话临时密钥，自带前向保密；旧的静态 15min 令牌窗口消失 |
| 设备失窃 | 设备私钥存安全区（Keychain 已实现）；app 内按设备吊销（移除授权列表中的静态公钥），不动 VPS authorized_keys |
| **白名单式 DPI（只放已知协议）** | 由 SSH 载体兜住——Noise 不透明 TCP 被包在合法的 SSH 内，不再裸奔。**这是选 SSH 而非裸 Noise 的关键** |
| 把自己锁在门外 | SSH 端口优先 accept；loopback Noise 口免规则；agent 拒绝自锁操作（沿用 0003 §5 思路） |

## 迁移

- **破坏性**：传输与身份密钥都变（TLS→Noise、Ed25519 设备身份→X25519 静态）。设备需**重新配对**（设备数少，可接受）。
- **agent**：保留旧 `19186` TLS 监听一个过渡期 vs 一刀切——倾向**一刀切**（目标环境本就不许那条 TLS 端口存在，留着违背初衷）。
- **客户端 store**：`fingerprint` 字段 → `noise_pubkey`；新增 `ssh_port` / 受限 key 引用；store 版本号 +1，首启迁移或提示重配。
- **QR**：payload `v:1` → `v:2`，客户端兼容解析两版（v1 走旧流程的过渡期内）。

## 影响 / 后续

- **驱动 proto**：新增 Noise 握手载荷、JSON-RPC 信封类型；移除 `AuthChallenge`/`AuthVerify`/`SessionToken`。
- **驱动 ADR 0002**：nft 不变量从「管理端口」改述为「SSH 端口」优先 accept。
- **驱动 ADR 0004（部署）**：`ipgate-agent pair --qr` 输出受限转发 key 与 Noise 静态公钥；systemd 不再暴露 19186，agent 仅 loopback；安装脚本写入受限 `authorized_keys` 条目。
- **移动端**：russh 在 iOS/Android 的真机构建与电量/后台连接行为需验证（纯 Rust，预期可行）。

## 已决（2026-06-26 定稿）

1. **内层编码 = JSON-RPC**。彻底去 HTTP、去 axum/reqwest；每条 Noise transport 消息 = 一个 `{op, body}` → `{ok|err, data}`。
2. **SSH 凭据 = 单把共享受限 key**（`restrict,permitopen="127.0.0.1:NPORT",command=""`，no-pty/no-shell）。per-device 吊销由 Noise 授权列表负责，SSH 层只给「到达权」。
3. **启用 `Noise_IKpsk0`**（注：早稿误写 psk2。psk2 仅在 msg2 混入 PSK，响应方仍会处理 msg1 并回包＝可探测；**psk0** 在 msg1 之前就混入 PSK，无 PSK 者连合法 msg1 都造不出、响应方静默拒绝，才真正「不可探测」）。PSK = 现 access-key 的 128-bit；access-key 不再做 HTTP 门，转生为 Noise PSK。
