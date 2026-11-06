//! agent 配置。

use crate::store::RulesetFlags;
use anyhow::{bail, Context, Result};
use ipgate_proto::{
    ForwardProto, PortRange, PublicPort, RulesetConfig, SshKnock, DEFAULT_MGMT_PORT,
    DEFAULT_SSH_PORT,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// 已弃用（ADR 0007）：Noise 服务恒绑 `127.0.0.1:mgmt_port`，此字段不再决定监听地址。
    pub bind: SocketAddr,
    /// Noise 服务在 loopback 上监听的端口（SSH 隧道转发到此）。**永不**进受管名单。
    pub mgmt_port: u16,
    /// SSH 管理端口：ruleset 无条件放行的自锁不变量端口（ADR 0007，唯一入口）。默认 22。
    pub ssh_port: u16,
    /// SSH 隧道登录用户（客户端经它建隧道、转发到本机 Noise 口；写进配对二维码）。默认 root。
    pub ssh_user: String,
    /// 对全世界开放的 TCP 端口/区间。
    pub public_tcp: Vec<PortRange>,
    /// 对全世界开放的 UDP 端口/区间。
    pub public_udp: Vec<PortRange>,
    /// 数据目录（存储、密钥、证书）。
    pub data_dir: PathBuf,
    /// 管理 API 访问密钥门：要求每个请求带 `X-Ipgate-Key`，否则一律 404（端口对外「变暗」）。
    ///
    /// **默认 false**：升级既有部署时不会突然把现有客户端挡在门外（盲改 = 自找麻烦）。
    /// 全新安装由 install.sh 写成 true 并打印 join 串。开启前请确认客户端已带上访问密钥。
    pub require_access_key: bool,
    /// 每源 IP 每分钟最大请求数（0 = 不限）。挡探测/刷量/暴力。默认 120，对正常轮询绰绰有余。
    pub rate_limit_per_min: u32,
    /// dnat 适配（ADR 0006，排空模型）：统一查看/删除本机 dnat 规则；新增走 native。默认关。
    pub dnat: crate::dnat::DnatAdapterConfig,
    /// SSH 敲门参数（ADR 0012），由 access key 派生、不进 config.json。要落 ruleset 的命令
    /// 经 [`Self::with_knock`] 填入；为 `None` 时「仅名单」不带敲门。
    #[serde(skip)]
    pub ssh_knock: Option<SshKnock>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_MGMT_PORT),
            mgmt_port: DEFAULT_MGMT_PORT,
            ssh_port: DEFAULT_SSH_PORT,
            ssh_user: "root".to_string(),
            public_tcp: Vec::new(),
            public_udp: Vec::new(),
            data_dir: PathBuf::from("/var/lib/ipgate"),
            // 默认关：保升级不锁现有客户端。全新安装由 install.sh 置 true。
            require_access_key: false,
            rate_limit_per_min: 120,
            dnat: crate::dnat::DnatAdapterConfig::default(),
            ssh_knock: None,
        }
    }
}

impl AgentConfig {
    /// 从 JSON 文件加载；文件不存在时返回默认配置。
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("读取配置失败: {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("解析配置失败: {}", path.display()))
        } else {
            Ok(Self::default())
        }
    }

    /// 读 access key（不存在则生成）派生敲门参数。
    pub fn with_knock(mut self) -> Result<Self> {
        let key = crate::auth::access::load_or_generate(&self.data_dir)?;
        self.ssh_knock = Some(crate::auth::derive_knock(&key));
        Ok(self)
    }

    /// 只读、尽力派生敲门参数：救援 / 审计命令不能被损坏的 access.key 卡住，也不该顺手生成它。
    pub fn try_with_knock(mut self) -> Self {
        match crate::auth::access::load(&self.data_dir) {
            Ok(key) => self.ssh_knock = Some(crate::auth::derive_knock(&key)),
            Err(e) => eprintln!(
                "警告：读不到 access.key（{e:#}），本次不带 SSH 敲门规则——SSH 若为「仅名单」，只有名单内 IP 能连。"
            ),
        }
        self
    }

    /// 校验不变量：管理端口不能为 0，否则会把自己锁死（ADR 0002/0003）。
    pub fn validate(&self) -> Result<()> {
        if self.mgmt_port == 0 {
            bail!("mgmt_port 不能为 0（Noise loopback 监听端口）");
        }
        if self.ssh_port == 0 {
            bail!("ssh_port 不能为 0（ruleset 靠它放行 SSH——唯一入口，置 0 会锁死自己）");
        }
        for p in self.public_tcp.iter().chain(&self.public_udp) {
            if !p.is_valid() {
                bail!("非法端口区间: {}-{}", p.start, p.end);
            }
        }
        Ok(())
    }

    /// 构造 ruleset 配置；`flags` 是运行期设置（存在 store），由调用方注入。
    /// 公开端口 = config.json 的 + 客户端添加的（重叠区间由渲染层合并）。
    pub fn ruleset_with(&self, flags: RulesetFlags) -> RulesetConfig {
        let mut public_tcp = self.public_tcp.clone();
        let mut public_udp = self.public_udp.clone();
        for p in &flags.public_ports {
            if p.proto != ForwardProto::Udp {
                public_tcp.push(p.ports);
            }
            if p.proto != ForwardProto::Tcp {
                public_udp.push(p.ports);
            }
        }
        RulesetConfig {
            ssh_port: self.ssh_port,
            ssh_allowlist_only: flags.ssh_allowlist_only,
            ssh_knock: self.ssh_knock.clone(),
            forward_allowlist_only: flags.forward_allowlist_only,
            public_tcp,
            public_udp,
        }
    }

    /// 覆盖 SSH 端口的 TCP 公开端口（config.json 的 + 客户端添加的）。存在时「SSH 仅名单可连」不生效。
    pub fn public_port_covering_ssh(&self, flags: &RulesetFlags) -> Option<PublicPort> {
        self.config_public_ports()
            .into_iter()
            .chain(flags.public_ports.iter().cloned())
            .find(|p| self.covers_ssh(p.proto, p.ports))
    }

    pub fn covers_ssh(&self, proto: ForwardProto, ports: PortRange) -> bool {
        proto != ForwardProto::Udp && ports.contains(self.ssh_port)
    }

    /// config.json 里的公开端口（只读展示用）。
    pub fn config_public_ports(&self) -> Vec<PublicPort> {
        let tcp = self.public_tcp.iter().map(|&r| (ForwardProto::Tcp, r));
        let udp = self.public_udp.iter().map(|&r| (ForwardProto::Udp, r));
        tcp.chain(udp)
            .map(|(proto, ports)| PublicPort { proto, ports, note: String::new(), from_config: true })
            .collect()
    }

    pub fn store_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports() {
        let c = AgentConfig::default();
        assert_eq!(c.mgmt_port, 19186);
        assert_eq!(c.ssh_port, 22);
        assert_eq!(c.ruleset_with(RulesetFlags::default()).ssh_port, 22);
        c.validate().unwrap();
    }

    #[test]
    fn rejects_zero_mgmt_port() {
        let c = AgentConfig {
            mgmt_port: 0,
            ..AgentConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_zero_ssh_port() {
        let c = AgentConfig {
            ssh_port: 0,
            ..AgentConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn runtime_public_ports_merge_with_config() {
        let c = AgentConfig { public_tcp: vec![PortRange::single(443)], ..AgentConfig::default() };
        let p = |proto, port| PublicPort {
            proto,
            ports: PortRange::single(port),
            note: String::new(),
            from_config: false,
        };
        let flags = RulesetFlags {
            public_ports: vec![p(ForwardProto::Both, 25565), p(ForwardProto::Udp, 53)],
            ..RulesetFlags::default()
        };
        let r = c.ruleset_with(flags);
        assert_eq!(r.public_tcp, vec![PortRange::single(443), PortRange::single(25565)]);
        assert_eq!(r.public_udp, vec![PortRange::single(25565), PortRange::single(53)]);
    }

    #[test]
    fn partial_config_fills_defaults() {
        // 只给 mgmt_port，其余走默认（serde(default)）。
        let c: AgentConfig = serde_json::from_str(r#"{"mgmt_port": 20000}"#).unwrap();
        assert_eq!(c.mgmt_port, 20000);
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/ipgate"));
    }
}
