# ADR 0004：agent 部署形态

状态：已定案
日期：2026-06-24
关联：ADR 0002（nftables / default-drop）、ADR 0003（TLS/鉴权）

## 背景

agent 要部署到任意 Linux VPS 上长期运行。default-drop 模型（ADR 0002）带来一个**致命运维风险**：一旦应用 ruleset，除管理端口（19186）+ established + 放行名单 + 公开端口外**一律拒**——包括 **SSH**。在远程主机上裸装会把管理员锁在门外。

## 决策

| 维度 | 选择 |
|------|------|
| 运行身份 | **root**（最省事、兼容性最好；遇 cap 问题无需排查 ambient capability） |
| 分发 | **静态 musl 单二进制**（x86_64 / aarch64-unknown-linux-musl），无运行时依赖，拷贝即用 |
| 开机顺序 | **防火墙提前**：systemd unit `Before=network-pre.target`，网卡配置前建立 default-drop，关闭暴露窗口（同 ufw/firewalld 做法） |
| 持久化 | 不写 `/etc/nftables.conf`；agent 启动即原子重建 + 对账循环兜底（内核被外部清掉会在一个 interval 内自愈） |
| 防自锁 | 安装脚本检测 `$SSH_CONNECTION` 的来源 IP，先 `ipgate-agent allow <ip>` 注入放行名单，再启动服务 |

## 文件布局

| 路径 | 内容 |
|------|------|
| `/usr/local/bin/ipgate-agent` | 二进制 |
| `/etc/ipgate/config.json` | 配置（bind / mgmt_port / public_tcp,udp / data_dir） |
| `/var/lib/ipgate/` | 数据：`state.json`、`cert.pem`/`key.pem`、`secret.bin`、`pairing.json`（0700） |
| `/etc/systemd/system/ipgate-agent.service` | systemd unit |

## systemd unit 要点

- `Type=simple`，`ExecStart=… run`，`Restart=on-failure`。启动即应用 ruleset；失败则退出非 0 → 重启重试。
- `Wants=network-pre.target` + `Before=network-pre.target`：防火墙在网络起来前就位。绑定 `0.0.0.0:19186` 在网卡未配置时也能成功，accept 自然等到网络就绪。
- 加硬（root 下仍尽量收敛）：`NoNewPrivileges`、`ProtectSystem=strict` + `ReadWritePaths=/var/lib/ipgate`、`ProtectHome`、`PrivateTmp`。
  - **不可过严**：nft 需 netlink，故 `RestrictAddressFamilies` 必须含 `AF_NETLINK`（及 AF_UNIX/AF_INET/AF_INET6）；不启用会屏蔽 netlink 的 `ProtectKernelTunables` 等。
- 不设 `After=nftables.service`：避免与系统 nft 加载的排序死结；改由对账循环兜底。

## 安装脚本（install.sh）职责

1. 需 root；定位二进制（`--binary` 或脚本同目录的 `ipgate-agent[-<arch>]`）。
2. **前置检查**：`nft` 存在；探测 **ufw/firewalld** 启用 → 醒目警告（ADR 0002：default-drop 应独占，drop 裁决终局）。
3. 装二进制 → 建 `/etc/ipgate`（写默认配置，若无）→ 建 `/var/lib/ipgate`（0700）。
4. **防自锁**：若经 SSH 安装（`$SSH_CONNECTION`），把来源 IP 以 `/32`或`/128` 注入放行名单。
5. 装 unit → `daemon-reload` → `enable --now`。
6. 跑 `ipgate-agent pair` 打印首个配对码 + 指纹，引导客户端入网。

幂等：已存在的配置/数据不覆盖。

## 卸载脚本（uninstall.sh）职责

- `disable --now` + 删 unit + `daemon-reload`。
- `ipgate-agent uninstall`（flush `inet ipgate` 表）——**醒目提示这会拆掉防火墙**。
- 询问是否删 `/var/lib/ipgate`、`/etc/ipgate`、二进制。

## 构建（build-release.sh）

用 `cross`（容器化，免搭 musl 工具链）交叉编译两个 target 到 `dist/`。workspace 根使得 `../proto` 路径依赖在容器挂载内可解析（本 ADR 顺带把 ipgate 收进 Cargo workspace）。

## 影响 / 后续

- 引入离线 CLI：`ipgate-agent allow/revoke <CIDR>`（写存储 + 尽力落内核）。**仅供离线/安装期**：服务运行中应走 API，否则 CLI 直接加的内核元素会被对账循环当 stale 撤掉。
- root 运行是 v1 取舍；后续可选「专用用户 + AmbientCapabilities=CAP_NET_ADMIN」收敛权限。
- 加硬项（限速/锁定、审计日志，ADR 0003）仍待补。
