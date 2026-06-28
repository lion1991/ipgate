# agent

跑在**远程 Linux 主机**上的服务端进程，唯一有权读写 nftables 的组件。

## 职责

- 对客户端暴露 API：**JSON-RPC over Noise_IKpsk0**，仅 loopback 监听、经 **SSH 隧道**访问（[ADR 0007](../docs/adr/0007-noise-over-ssh.md)，取代 0003 的 TLS/REST）。
- 把放行名单落地到 nftables：`nft` 子进程，全主机 default-drop，独占 `inet ipgate` 表（[ADR 0002](../docs/adr/0002-nftables-backend.md)）。
- 读取内核实际状态，支持与客户端**同步 (Sync)**。
- 清理过期条目（agent 对账权威 + 内核 timeout 兜底），记录放行/撤销审计日志。

## 模块

面向内核的半边（ADR 0002）：

| 模块 | 内容 |
|------|------|
| `nft` | `NftBackend` trait + `NftCli`（`nft` 子进程）；`ruleset.rs` 渲染 `inet ipgate` 原子事务、`nat.rs` 渲染 `ip ipgate_nat` 转发表（`NatBackend`）、`parse.rs` 解析 `nft -j` |
| `forward` | 端口转发编排（ADR 0005）：解析目标/网卡/源 → 渲染 → 落地；`resolve` 域名解析、`netinfo` 网卡/默认路由/ip_forward |
| `config` | `AgentConfig`（mgmt_port=loopback Noise 口、ssh_port/ssh_user、public_tcp/udp、data_dir）+ `validate()` 拒自锁 |
| `store` | 条目/设备/转发 JSON 持久化（原子写）+ allow/revoke/prune/设备/转发管理 + 解析缓存 |
| `reconcile` | 期望态 vs 内核态求 `Diff`（missing/stale/expired） |

面向客户端的半边（ADR 0007）：

| 模块 | 内容 |
|------|------|
| `noise` | `NoiseIdentity`（X25519 静态密钥，0600 持久化）+ `Noise_IKpsk0` 握手（responder）+ 长度前缀分帧 AEAD 收发 + `derive_psk`（access key→PSK） |
| `auth` | `pairing`（配对码，文件跨进程、单次限时）/ `access`（访问密钥 = Noise PSK 来源） |
| `api` | loopback TCP 监听 + `serve`/握手鉴权（含配对）+ **JSON-RPC dispatcher**（`RpcRequest`→handler）+ per-IP 限流 |
| `main` | CLI：`run`（守护进程）/ `pair [--qr --host]` / `access-key` / `forwards` / `forward-add` / `forward-rm` / `ssh-expose` / `print-ruleset` / `status` / `uninstall` |

## CLI

```sh
ipgate-agent --config <path> pair [--qr --host <地址>]  # 生成配对口令「访问密钥.配对码」+ 打印 Noise 公钥；--qr 出含隧道凭据的二维码
ipgate-agent --config <path> access-key      # 打印访问密钥（= Noise 握手 PSK；--reset 轮换后需 restart + 重配对）
ipgate-agent --config <path> run             # 守护进程：应用 ruleset + 后台对账 + Noise JSON-RPC（loopback，需 root + nftables）
ipgate-agent --config <path> allow <CIDR>    # 离线放行（写存储，安装时防自锁用；运行中请走 API）
ipgate-agent --config <path> revoke <CIDR>   # 离线撤销
ipgate-agent --config <path> forwards        # 列端口转发规则（+ 当前解析 IP）
ipgate-agent --config <path> forward-add --listen 443 --dest 10.0.0.9:8443 [--proto both] [--iface eth0] [--source auto]
ipgate-agent --config <path> forward-rm <id> # 删端口转发（按 id）
ipgate-agent --config <path> ssh-expose --open       # SSH 端口对所有人开放（控制台救援：解除「仅名单」自锁）
ipgate-agent --config <path> ssh-expose --allowlist  # SSH 端口仅放行名单内源 IP 可连
ipgate-agent --config <path> print-ruleset   # 打印将应用的 nft ruleset（不改内核，便于审计）
ipgate-agent status                          # 存储条目 + 内核 set 状态
ipgate-agent uninstall                       # flush 掉 inet ipgate 表
```

## 部署（ADR 0004）

`deploy/` 下：systemd unit、配置样例、安装/卸载/构建脚本。

```sh
deploy/build-release.sh          # cross 交叉编译静态 musl 二进制 → dist/
# 把 dist/ipgate-agent-<arch> + deploy/* 拷到目标主机后：
sudo deploy/install.sh           # root；探测 ufw/firewalld、生成仅转发隧道密钥、起服务（loopback Noise）、打印配对口令
sudo deploy/uninstall.sh --purge # 停服务 + flush 表 + 删数据
```

> ⚠️ default-drop 一旦生效，除 **SSH 端口（`ssh_port`，默认 22，无条件放行）**/established/放行名单/公开端口外一律拒。SSH 是唯一入口、结构性**不自锁**（ADR 0007）；其余对外服务端口请写进 `public_tcp`。
>
> 🔒 **SSH 仅名单可连**（可选，默认关）：客户端开关或 `ssh-expose --allowlist` 可把 22 收窄为仅放行名单内源 IP 可连（去掉无条件放行，改由 `saddr @allow` 命中）。有自锁风险——开启前先放行自己；锁死了从控制台 `ssh-expose --open` 恢复。状态存 `state.json`（`ssh_allowlist_only`）。

## API（JSON-RPC over Noise，仅 loopback；经 SSH 隧道访问，ADR 0007）

> **传输**：agent 只在 `127.0.0.1:mgmt_port` 监听 `Noise_IKpsk0`。客户端用单把「仅转发」SSH key
> 建隧道转发到该口，再跑 Noise 握手。线上只有 SSH 流量——无 TLS、无 HTTP、无公网监听端口。
> **PSK**（= 访问密钥）混进握手 psk0：不持有者连合法握手都造不出，agent 静默拒绝（端口「变暗」）。
> **鉴权**：握手即完成——客户端 X25519 静态公钥就是设备身份；新设备须在握手载荷带有效配对码。

> **dnat 适配**（`dnat.enabled`，ADR 0006 排空模型）：统一列表纳入外部 dnat 工具创建的转发，
> 支持查看/删除/「迁移到 agent」。install.sh 写出的默认配置置 `true`，但仅当本机确有 dnat
> （`base_dir` + `bin` 存在）才激活，否则静默 inert。代码 serde 默认为 `false`——**升级既有部署
> 不会自动开**，需在 `/etc/ipgate/config.json` 显式加 `"dnat": {"enabled": true}` 并重启。

```
握手（一次）：配对 / 设备鉴权折进 Noise 握手（含配对码消费）
RPC op（握手后，隧道内 JSON）：
  list_allowlist / allow / revoke           放行名单 列出 / 放行 / 撤销
  sync                                      内核 vs 存储差异
  list_forwards / add_forward / remove_forward          端口转发（ADR 0005）
  remove_dnat / migrate_dnat                dnat 适配（ADR 0006）
  list_interfaces                           列主机网卡（客户端下拉用）
  list_devices / revoke_device              已授权设备 / 吊销
  get_settings / set_ssh_exposure           读取设置（SSH 暴露模式 + 端口 + sshd 密码登录态势）/ 切换 SSH 端口暴露（仅名单↔对所有人）
  whoami                                    回报对端 IP（注：SSH 隧道下为 loopback）
```

> **端口转发**（ADR 0005）：DNAT/SNAT 落在**独立** `ip ipgate_nat` 表，与放行名单 `inet ipgate`
> 彻底隔离——转发渲染出错也碰不到管理端口不变量。目标可填域名（周期重解析、失败回退上次 IP）。
> 转发端口走 forward hook，**不过**放行名单（标准转发语义）。

## 开发

```sh
cargo test                  # 73 项：Noise 握手/配对 + 放行→撤销 + 端口转发 CRUD + SSH 暴露切换 端到端（真 TCP+Noise）+ ruleset/nat 渲染 + 隧道密钥种子抽取 + sshd 认证态势解析
cargo clippy --all-targets
cargo run -- --config <cfg> print-ruleset   # 非 Linux 可跑（纯渲染）
cargo run -- --config <cfg> pair            # 非 Linux 可跑（生成 Noise 密钥 + 配对码）
```

## 待办

- [x] 定 ADR 0002 / 0003
- [x] 面向内核：`NftBackend` + 幂等重建（坐实不变量）+ 对账 / 存储 / 配置
- [x] 面向客户端：~~TLS+TOFU + REST（axum）~~ → **Noise_IKpsk0 over SSH 隧道 + JSON-RPC**（ADR 0007）
- [ ] 定 ADR 0004（部署形态）；systemd unit + 安装脚本（`CAP_NET_ADMIN`、探测 ufw/firewalld、flush 选项）
- [ ] 在一台测试 VPS 上跑通 `run` + 用真实客户端打通配对/放行
- [x] 管理端口加硬：访问密钥门（端口「变暗」）+ per-IP 限流（ADR 0003 §4）
- [x] 名单外 IP 禁 ping（ICMP echo 仅放名单源；PMTUD 错误类仍放，防黑洞）
- [x] 端口转发（DNAT/SNAT，独立 `ip ipgate_nat` 表，域名重解析，ADR 0005）
- [ ] 端口转发 Phase 2：可选「只放名单内源 IP」（nat 表内同步名单副本）；IPv6 目标
- [ ] fail2ban 式连续失败锁定 / 审计日志 / 实时同步 WebSocket；mTLS 双向证书（防御纵深）
