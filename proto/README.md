# ipgate-proto

客户端与 agent 共享的协议类型（Rust crate，serde），**单一可信源**，避免两端结构体漂移。

只放**类型与常量**，不含传输/落地实现。设计依据见 [`../docs/adr/`](../docs/adr/)。

## 模块

| 模块 | 内容 |
|------|------|
| `entry` | `Entry` / `AllowRequest` / `RevokeRequest` / `Allowlist`（条目用 `ipnet::IpNet`，支持 CIDR） |
| `auth` | `Device` / `PairRequest`·`PairResponse` / `AuthChallenge*` / `AuthVerify*`（ADR 0003） |
| `ruleset` | `RulesetConfig`（`mgmt_port`、`public_tcp/udp`）/ `PortRange` / `KernelElement` / `Diff`（ADR 0002） |
| `crypto` | `PublicKey` / `Signature` / `Nonce` / `SpkiFingerprint` / `PairingCode`·`SessionToken`（后两者 Debug 脱敏） |
| `ids` | `DeviceId` / `EntryId`（UUID newtype） |
| `error` | `ApiError` / `ErrorCode`（含 `WouldLockOut` 等不变量错误码） |

顶层常量：`DEFAULT_MGMT_PORT = 19186`、`API_VERSION`、`NFT_TABLE`/`NFT_SET_*`、各 TTL。

## 设计取舍

- **不依赖任何密码学库**：公钥/签名/nonce 以 base64 字符串承载、指纹以十六进制承载，编解码与验签是 agent/client 的事。proto 保持轻、无 C 依赖。
- 机密 newtype（`PairingCode`/`SessionToken`）的 `Debug` 脱敏，不实现 `Display`，防误入日志。
- 时间统一 `chrono::DateTime<Utc>`（线上 RFC3339）。

## 开发

```sh
cargo test     # 5 个 serde 往返 / 不变量测试
cargo clippy --all-targets
```

## 状态

✅ 已实现并通过测试/clippy。后续随 agent/client 落地按需补字段（如每条目端口细分）。
