# agent

跑在**远程 Linux 主机**上的服务端进程，唯一有权读写 nftables 的组件。

## 安装

**前置条件**：Linux x86_64（Releases 目前只发 x86_64；其他架构见[开发](#开发)自行交叉编译后用 `--binary`）、
systemd、nftables（有 `nft` 命令）、root。正在运行的 ufw / firewalld 会和 ipgate 冲突，脚本会提示，建议先停掉。

> ⚠️ **装之前先看**：装完后整台主机**默认拒绝入站**，只放行这几类：
> - SSH 端口：自动探测，无条件放行，不会把你锁在外面；
> - 已建立的连接；
> - 放行名单里的 IP：安装时会把你当前的 SSH 来源 IP 加进去；
> - 公开端口：对所有 IP 开放的端口。
>
> 本机对外提供的服务（网站 80/443 等）装完后要加进公开端口，否则会被挡掉。可以在客户端里加，或写进
> `/etc/ipgate/config.json` 的 `public_tcp` / `public_udp` 后 `systemctl restart ipgate-agent`。
> 全新安装还会开启[转发名单门](#部署细节adr-0004)：端口转发和 Docker `-p` 映射的端口同样只对名单内 IP 和公开端口开放。

**一键安装**：

```sh
curl -fsSL https://raw.githubusercontent.com/lion1991/ipgate/main/agent/deploy/install.sh | sudo bash
```

**离线安装**：从 [Releases](https://github.com/lion1991/ipgate/releases) 下载
`ipgate-agent-x86_64-unknown-linux-musl.tar.gz`，拷到主机上解压后运行 `sudo ./install.sh`（用包里的二进制，不联网下载）。

常用参数（`curl | sudo bash` 时写成 `sudo bash -s -- <参数>`）：

| 参数 | 作用 |
|------|------|
| `--allow <IP>` | 额外放行一个管理来源 IP。`curl \| bash` 下有时探测不到你的 SSH 来源 IP，可以用它补上 |
| `--version vX.Y.Z` | 装指定版本（默认最新） |
| `--yes` / `-y` | 跳过所有确认，无人值守安装 |
| `--force` | 已是目标版本也重新安装 |
| `--binary <路径>` | 用本地二进制，不下载 |
| `--server <URL>` / `--repo <owner/name>` | 从其他站点或仓库下载 release（如自建的 Forgejo 镜像） |

脚本做的事：下载二进制并校验 SHA256 → 写 `/etc/ipgate/config.json`（已存在则保留）→ 生成一把「仅转发」的
SSH 隧道密钥（只能转发到 agent 的本机端口，不能登录）→ 起 systemd 服务 `ipgate-agent` → 首次安装时打印配对口令。

**装完配对**：把脚本最后打印的「访问密钥.配对码」整串粘进客户端的「配对码」栏。手机上可以扫码，一步完成配对和隧道配置：

```sh
sudo ipgate-agent pair --qr --host <服务器地址>   # 生成含隧道凭据的二维码；不带 --qr 则只重新打印口令
```

检查状态：`systemctl status ipgate-agent`、`sudo ipgate-agent status`、`sudo nft list table inet ipgate`。

**升级**：`sudo ipgate-update`。它会记住安装时的下载源，原地升级，配置、名单和已配对设备都保留；参数透传给 install.sh
（如 `--version vX.Y.Z`）。

**卸载**：运行 release 包里或仓库 `agent/deploy/` 下的 `sudo ./uninstall.sh`。它会停掉服务、拆掉 ipgate 的防火墙规则、
删除二进制和隧道公钥；配置与数据（`/etc/ipgate`、`/var/lib/ipgate`）会询问是否删除，`--purge` 直接删。

**进不去了怎么办**：SSH 端口默认对所有 IP 开放，不会因为名单锁死。如果开了「SSH 仅名单可连」又连不上，
从云厂商控制台登录执行 `sudo ipgate-agent ssh-expose --open` 恢复。

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
| `main` | CLI：`run`（守护进程）/ `pair [--qr --host]` / `access-key` / `forwards` / `forward-add` / `forward-rm` / `ssh-expose` / `forward-expose` / `print-ruleset` / `status` / `uninstall` |

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
ipgate-agent --config <path> ssh-expose --allowlist  # SSH 端口仅放行名单内源 IP 与敲过门的已配对设备可连（ADR 0012）
ipgate-agent --config <path> forward-expose --allowlist  # 转发（含 Docker 映射）仅放行名单内源 IP 与公开端口（ADR 0008）
ipgate-agent --config <path> forward-expose --open       # 转发对所有人开放（控制台救援）
# ssh-expose / forward-expose 成功后，若服务在运行会自动 systemctl restart，免得服务内存里的旧开关把改动撤销
ipgate-agent --config <path> print-ruleset   # 打印将应用的 nft ruleset（不改内核，便于审计）
ipgate-agent status                          # 存储条目 + 内核 set 状态
ipgate-agent uninstall                       # flush 掉 inet ipgate 表
```

## 部署细节（ADR 0004）

`deploy/` 下：systemd unit、配置样例、安装/卸载/构建脚本。安装步骤见[安装](#安装)。

> ⚠️ default-drop 一旦生效，除 **SSH 端口（`ssh_port`，默认 22，无条件放行）**/established/放行名单/公开端口外一律拒。SSH 是唯一入口、结构性**不自锁**（ADR 0007）；其余对外服务端口请写进 `public_tcp`。
>
> 🔒 **SSH 仅名单可连**（可选，默认关）：客户端开关或 `ssh-expose --allowlist` 可把 22 收窄为仅放行名单内源 IP 与**敲过门**的源 IP 可连（ADR 0012）。已配对客户端连接前自动往 UDP 敲门端口（由 access key 派生，`status` 可查）发一个口令包，内核把源 IP 放行 60 秒，所以换了网络的设备也能进。**云安全组须放行该 UDP 端口**。内核不支持敲门时拒绝开启。敲门也不通、名单里也没有自己时，从控制台 `ssh-expose --open` 恢复。状态存 `state.json`（`ssh_allowlist_only`）。
>
> 🚪 **转发名单门**（可选；代码默认关，install.sh 全新安装时开启，ADR 0008）：被 DNAT 进来的新建连接（ipgate 转发、dnat 工具、Docker `-p`）也只放行名单内源 IP 与 `public_tcp/udp`（按 DNAT 前的原端口）。不经 input，不会自锁。内核不支持时自动退回无门 ruleset，并上报未生效。状态存 `state.json`（`forward_allowlist_only`）。

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
  list_forwards / add_forward / update_forward / remove_forward   端口转发（ADR 0005；update 原地改、保留 id）
  remove_dnat / migrate_dnat                dnat 适配（ADR 0006）
  list_interfaces                           列主机网卡（客户端下拉用）
  list_devices / revoke_device              已授权设备 / 吊销
  get_settings / set_ssh_exposure           读取设置（SSH 暴露模式 + 端口 + 敲门端口/生效态 + sshd 密码登录态势 + 转发门意图/生效态）/ 切换 SSH 端口暴露（仅名单↔对所有人）
  set_forward_exposure                      切换转发名单门（ADR 0008；先落内核再落盘，失败不改设置，错误附 nft 原文）
  set_ssh_password_auth / reset_root_password 开/关 sshd 密码登录（主配置顶部受管块+reload，sshd -t 校验，失败回滚）/ 重置 root 密码（chpasswd）
  whoami                                    回报对端 IP（注：SSH 隧道下为 loopback）
```

> **端口转发**（ADR 0005）：DNAT/SNAT 落在**独立** `ip ipgate_nat` 表，与放行名单 `inet ipgate`
> 彻底隔离——转发渲染出错也碰不到管理端口不变量。目标可填域名（周期重解析、失败回退上次 IP）。
> 转发端口走 forward hook，默认**不过**放行名单（标准转发语义），开启转发名单门后受名单约束（ADR 0008）。

## 开发

```sh
cargo test                  # agent + proto：Noise 握手/配对 + 放行→撤销 + 端口转发增删改 + SSH 暴露 / 转发名单门切换 端到端（真 TCP+Noise）+ ruleset/nat 渲染 + 隧道密钥种子抽取 + sshd 认证态势解析/受管块插入·剥离
cargo clippy --all-targets
cargo run -- --config <cfg> print-ruleset   # 非 Linux 可跑（纯渲染）
cargo run -- --config <cfg> pair            # 非 Linux 可跑（生成 Noise 密钥 + 配对码）
deploy/build-release.sh                     # cross 交叉编译静态 musl 二进制（x86_64 + aarch64）→ dist/
# 自编二进制装到主机：把 dist/ipgate-agent-<arch> 与 deploy/* 拷到同一目录，sudo ./install.sh 会优先用同目录二进制
```

> **发版**：`git tag -a vX.Y.Z` 后推到 `origin`（GitHub）与自建 Forgejo 镜像，两边 CI 各自
> 构建并发布同名资产的 release：GitHub 走 `.github/workflows/`，Forgejo 走 `.forgejo/workflows/`（runner
> 标签 `go`；有了它 Forgejo 就不再读 `.github/`）。Forgejo 的 release 也可在 Actions 页手动运行补发旧 tag。
> `install.sh` 默认从 GitHub 下载；`--server https://<Forgejo 站点>`（或 `IPGATE_SERVER`）改走 Forgejo 镜像。
> 装完会生成 `/usr/local/bin/ipgate-update`（记住本次来源），之后在服务器上 `ipgate-update` 即原地升级，
> 参数透传给 install.sh（如 `--force`、`--version vX.Y.Z`、`-y`）。

## 待办

- [x] 定 ADR 0002 / 0003
- [x] 面向内核：`NftBackend` + 幂等重建（坐实不变量）+ 对账 / 存储 / 配置
- [x] 面向客户端：~~TLS+TOFU + REST（axum）~~ → **Noise_IKpsk0 over SSH 隧道 + JSON-RPC**（ADR 0007）
- [x] 定 ADR 0004（部署形态）；systemd unit + 安装脚本（`CAP_NET_ADMIN`、探测 ufw/firewalld、flush 选项）
- [x] 在一台测试 VPS 上跑通 `run` + 用真实客户端打通配对/放行
- [x] 管理端口加硬：访问密钥门（端口「变暗」）+ per-IP 限流（ADR 0003 §4）
- [x] 名单外 IP 禁 ping（ICMP echo 仅放名单源；PMTUD 错误类仍放，防黑洞）
- [x] 端口转发（DNAT/SNAT，独立 `ip ipgate_nat` 表，域名重解析，ADR 0005）
- [ ] 端口转发 Phase 2：可选「只放名单内源 IP」（nat 表内同步名单副本）；IPv6 目标
- [ ] fail2ban 式连续失败锁定 / 审计日志 / 实时同步 WebSocket；mTLS 双向证书（防御纵深）
